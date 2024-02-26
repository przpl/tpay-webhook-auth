import assert from "node:assert";
import { X509Certificate, verify } from "node:crypto";

export class TpayWebhookAuth {
    private cachedRootCert: X509Certificate | null = null;

    constructor(private readonly options?: { sandboxMode?: boolean }) {}

    /**
     * Verifies the JWS signature of the request body sent by Tpay. Read more at https://api.tpay.com.
     * @param requestBody Buffer containing the raw request body.
     * @param jwsSignature JWS signature sent in the `x-jws-signature` header.
     */
    public async checkSignature(requestBody: Buffer, jwsSignature: string): Promise<boolean> {
        assert(Buffer.isBuffer(requestBody), `requestBody must be a buffer, got ${requestBody === null ? "null" : typeof requestBody}.`);
        assert(
            typeof jwsSignature === "string",
            `jwsSignature must be a string, got ${jwsSignature === null ? "null" : typeof jwsSignature}.`
        );

        const [headerBase64Url, , signatureBase64Url] = jwsSignature.split(".");
        assert(headerBase64Url && signatureBase64Url, "Invalid signature format. Either header or signature is missing.");

        const headerUtf8 = Buffer.from(headerBase64Url, "base64url").toString("utf8");
        const header: { alg: string; x5u: string } = JSON.parse(headerUtf8);

        const signingCert = await this.getSigningCert(header.x5u);

        const data = Buffer.from(headerBase64Url + "." + requestBody.toString("base64url"));
        const signature = Buffer.from(signatureBase64Url, "base64url");

        return verify("sha256", data, signingCert.publicKey, signature);
    }

    private async getSigningCert(url: string): Promise<X509Certificate> {
        const signingCert = await this.x5u(url);

        const isRootCertCached = Boolean(this.cachedRootCert);
        let rootCert = this.cachedRootCert;
        if (!rootCert) {
            rootCert = await this.root();
            this.cachedRootCert = rootCert;
        }

        if (!signingCert.verify(rootCert.publicKey)) {
            if (isRootCertCached) {
                // get the latest root cert and try again, maybe the root cert was changed by Tpay?
                rootCert = await this.root();
                this.cachedRootCert = rootCert;

                if (!signingCert.verify(rootCert.publicKey)) {
                    throw new Error("Signing certificate is not signed by Tpay CA certificate.");
                }
            }

            throw new Error("Signing certificate is not signed by Tpay CA certificate.");
        }

        return signingCert;
    }

    private async x5u(url: string): Promise<X509Certificate> {
        const expectedUrl = this.options?.sandboxMode ? "https://secure.sandbox.tpay.com" : "https://secure.tpay.com";
        if (!url.startsWith(expectedUrl)) {
            throw new Error(`"Unexpected x5u URL: '${url}'. Check if sandboxMode is set correctly.`);
        }

        return this.fetch(url);
    }

    private async root(): Promise<X509Certificate> {
        const url = this.options?.sandboxMode
            ? "https://secure.sandbox.tpay.com/x509/tpay-jws-root.pem"
            : "https://secure.tpay.com/x509/tpay-jws-root.pem";

        return this.fetch(url);
    }

    private async fetch(url: string) {
        const response = await fetch(url);
        if (!response.ok) {
            throw new Error(`Failed to fetch certificate from ${url}. Status: ${response.status}`);
        }

        const text = await response.text();
        return new X509Certificate(text);
    }
}
