import assert from "node:assert";
import { X509Certificate, verify } from "node:crypto";

/** How long a fetched certificate is reused before it is downloaded again, unless it expires sooner. */
const CERT_CACHE_TTL_MS = 60 * 60 * 1000;
/**
 * Minimum delay between root certificate downloads triggered by a failed chain check. Without it, a certificate that
 * does not chain to the root would cause one download per incoming request.
 */
const ROOT_REFETCH_THROTTLE_MS = 60 * 1000;
const FETCH_TIMEOUT_MS = 5_000;
const MAX_CERT_LENGTH = 64 * 1024;
/** Bounds the signing certificate cache so that certificate rotation cannot grow it without limit. */
const MAX_SIGNING_CERT_CACHE_SIZE = 16;
/** The only algorithm Tpay signs with. Pinned so that the header cannot pick a weaker one. */
const EXPECTED_ALG = "RS256";

interface CachedCert {
    cert: X509Certificate;
    expiresAt: number;
}

export class TpayWebhookAuth {
    private cachedRootCert: CachedCert | null = null;
    private rootCertRefetchAllowedAt = 0;
    private pendingRootCertFetch: Promise<X509Certificate> | null = null;
    private readonly cachedSigningCerts = new Map<string, CachedCert>();
    private readonly pendingSigningCertFetches = new Map<string, Promise<X509Certificate>>();

    constructor(private readonly options?: { sandboxMode?: boolean }) {}

    /**
     * Verifies the JWS signature of the request body sent by Tpay. Read more at https://api.tpay.com.
     * @param requestBody Buffer containing the raw request body.
     * @param jwsSignature JWS signature sent in the `x-jws-signature` header.
     * @returns `true` when the signature matches the body, `false` when it does not.
     * @throws When the request cannot be authenticated at all: a malformed signature, an x5u URL that is not a Tpay
     * URL, a certificate that cannot be fetched, or a certificate that is expired or not signed by the Tpay root. A
     * rejection is not a weaker `false`, treat it as a rejected webhook too.
     */
    public async checkSignature(requestBody: Buffer, jwsSignature: string): Promise<boolean> {
        assert(Buffer.isBuffer(requestBody), `requestBody must be a buffer, got ${requestBody === null ? "null" : typeof requestBody}.`);
        assert(
            typeof jwsSignature === "string",
            `jwsSignature must be a string, got ${jwsSignature === null ? "null" : typeof jwsSignature}.`
        );

        const segments = jwsSignature.split(".");
        assert(segments.length === 3, `Invalid signature format. Expected 3 dot-separated segments, got ${segments.length}.`);

        const [headerBase64Url, payloadBase64Url, signatureBase64Url] = segments;
        assert(headerBase64Url && signatureBase64Url, "Invalid signature format. Either header or signature is missing.");
        // Tpay sends a detached JWS: the payload is the request body, so the middle segment carries no meaning. A
        // non-empty one is never produced by Tpay and must not be waved through with the signature checking out anyway.
        assert(payloadBase64Url === "", "Invalid signature format. The payload segment must be empty.");

        const { x5u } = this.parseHeader(headerBase64Url);
        const signingCert = await this.getSigningCert(x5u);

        const data = Buffer.from(headerBase64Url + "." + requestBody.toString("base64url"));
        const signature = Buffer.from(signatureBase64Url, "base64url");

        return verify("sha256", data, signingCert.publicKey, signature);
    }

    private parseHeader(headerBase64Url: string): { x5u: string } {
        const headerUtf8 = Buffer.from(headerBase64Url, "base64url").toString("utf8");

        let header: unknown;
        try {
            header = JSON.parse(headerUtf8);
        } catch {
            throw new Error("Invalid signature format. Header is not valid JSON.");
        }

        assert(typeof header === "object" && header !== null, "Invalid signature format. Header is not a JSON object.");

        const { alg, x5u } = header as { alg?: unknown; x5u?: unknown };
        // The digest and key type are already fixed by checkSignature, so a forged 'alg' cannot weaken the check. This
        // keeps it that way if the header ever starts driving the verification.
        assert(alg === EXPECTED_ALG, `Invalid signature format. Expected the 'alg' field to be '${EXPECTED_ALG}'.`);
        assert(typeof x5u === "string", "Invalid signature format. Header is missing the 'x5u' field.");

        return { x5u };
    }

    private async getSigningCert(url: string): Promise<X509Certificate> {
        const cached = this.getCachedSigningCert(url);
        if (cached) {
            return cached;
        }

        const signingCert = await this.fetchSigningCert(url);
        this.assertCertIsCurrentlyValid(signingCert, "Signing");

        const rootCert = this.getCachedRootCert();
        if (!rootCert || !signingCert.verify(rootCert.publicKey)) {
            // Either there is no root cert yet, or the cached one does not match. Tpay may have rotated the root, so
            // download it again before rejecting the signing certificate.
            const latestRootCert = await this.refetchRootCert();
            if (!signingCert.verify(latestRootCert.publicKey)) {
                throw new Error("Signing certificate is not signed by Tpay CA certificate.");
            }
        }

        this.cacheSigningCert(url, signingCert);

        return signingCert;
    }

    /** Collapses concurrent requests for the same certificate into a single download. */
    private async fetchSigningCert(url: string): Promise<X509Certificate> {
        const pending = this.pendingSigningCertFetches.get(url);
        if (pending) {
            return pending;
        }

        const fetching = this.x5u(url).finally(() => this.pendingSigningCertFetches.delete(url));
        this.pendingSigningCertFetches.set(url, fetching);

        return fetching;
    }

    /**
     * A cached certificate never outlives its own validity window. Without the clamp, a certificate rotated by Tpay
     * halfway through the TTL would keep being served from the cache: expired, and so rejecting every webhook, until
     * the TTL lapsed.
     */
    private cacheEntry(cert: X509Certificate): CachedCert {
        return { cert, expiresAt: Math.min(Date.now() + CERT_CACHE_TTL_MS, cert.validToDate.getTime()) };
    }

    private getCachedSigningCert(url: string): X509Certificate | null {
        const cached = this.cachedSigningCerts.get(url);
        if (!cached) {
            return null;
        }

        this.cachedSigningCerts.delete(url);
        if (cached.expiresAt <= Date.now()) {
            return null;
        }

        // Reinsert so that eviction drops the least recently used entry. Otherwise a burst of unknown x5u URLs could
        // evict the one certificate Tpay actually signs with.
        this.cachedSigningCerts.set(url, cached);

        return cached.cert;
    }

    private cacheSigningCert(url: string, cert: X509Certificate): void {
        this.cachedSigningCerts.delete(url);
        while (this.cachedSigningCerts.size >= MAX_SIGNING_CERT_CACHE_SIZE) {
            const leastRecentlyUsedUrl = this.cachedSigningCerts.keys().next().value;
            if (leastRecentlyUsedUrl === undefined) {
                break;
            }
            this.cachedSigningCerts.delete(leastRecentlyUsedUrl);
        }

        this.cachedSigningCerts.set(url, this.cacheEntry(cert));
    }

    private getCachedRootCert(): X509Certificate | null {
        if (!this.cachedRootCert || this.cachedRootCert.expiresAt <= Date.now()) {
            return null;
        }

        return this.cachedRootCert.cert;
    }

    private async refetchRootCert(): Promise<X509Certificate> {
        const cached = this.getCachedRootCert();
        if (cached && Date.now() < this.rootCertRefetchAllowedAt) {
            return cached;
        }

        this.pendingRootCertFetch ??= this.fetchAndCacheRootCert().finally(() => (this.pendingRootCertFetch = null));

        return this.pendingRootCertFetch;
    }

    private async fetchAndCacheRootCert(): Promise<X509Certificate> {
        const rootCert = await this.root();
        this.assertCertIsCurrentlyValid(rootCert, "Root");

        this.cachedRootCert = this.cacheEntry(rootCert);
        this.rootCertRefetchAllowedAt = Date.now() + ROOT_REFETCH_THROTTLE_MS;

        return rootCert;
    }

    private assertCertIsCurrentlyValid(cert: X509Certificate, kind: "Signing" | "Root"): void {
        // X509Certificate.verify() only checks the signature, it ignores the validity period.
        const now = Date.now();
        if (now < cert.validFromDate.getTime()) {
            throw new Error(`${kind} certificate is not valid yet. It becomes valid at ${cert.validFrom}.`);
        }
        if (now > cert.validToDate.getTime()) {
            throw new Error(`${kind} certificate expired at ${cert.validTo}.`);
        }
    }

    private async x5u(url: string): Promise<X509Certificate> {
        let parsedUrl: URL;
        try {
            parsedUrl = new URL(url);
        } catch {
            throw new Error(`Unexpected x5u URL: '${url}'. It is not a valid URL.`);
        }

        // Comparing the parsed origin, not a string prefix. 'https://secure.tpay.com.example.com' and
        // 'https://secure.tpay.com@example.com' both start with the expected URL but point at another host.
        const isExpectedOrigin = parsedUrl.origin === this.baseUrl && !parsedUrl.username && !parsedUrl.password;
        // A query string or fragment does not change which certificate Tpay serves, but it does change the cache key.
        // Rejecting both keeps a caller from evicting the real signing certificate with endless URL variants.
        const isExpectedPath = parsedUrl.pathname.startsWith("/x509/") && !parsedUrl.search && !parsedUrl.hash;
        if (!isExpectedOrigin || !isExpectedPath) {
            throw new Error(`Unexpected x5u URL: '${url}'. Check if sandboxMode is set correctly.`);
        }

        return this.fetch(parsedUrl.href);
    }

    private async root(): Promise<X509Certificate> {
        return this.fetch(`${this.baseUrl}/x509/tpay-jws-root.pem`);
    }

    private get baseUrl(): string {
        return this.options?.sandboxMode ? "https://secure.sandbox.tpay.com" : "https://secure.tpay.com";
    }

    private async fetch(url: string) {
        // 'redirect: error' keeps the origin check meaningful, a redirect could otherwise send us to another host.
        const response = await fetch(url, { signal: AbortSignal.timeout(FETCH_TIMEOUT_MS), redirect: "error" });
        if (!response.ok) {
            throw new Error(`Failed to fetch certificate from ${url}. Status: ${response.status}`);
        }

        const contentLength = response.headers.get("content-length");
        if (contentLength !== null && Number(contentLength) > MAX_CERT_LENGTH) {
            throw new Error(`Certificate fetched from ${url} is too large.`);
        }

        const text = await response.text();
        if (text.length > MAX_CERT_LENGTH) {
            throw new Error(`Certificate fetched from ${url} is too large.`);
        }

        return new X509Certificate(text);
    }
}
