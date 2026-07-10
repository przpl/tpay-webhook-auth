import { X509Certificate } from "node:crypto";

import { TpayWebhookAuth } from "./tpayWebhookAuth";

const SIGNING_CERT_URL = "https://secure.tpay.com/x509/notifications-jws.pem";
const ROOT_CERT_URL = "https://secure.tpay.com/x509/tpay-jws-root.pem";

/** Valid from 2022-08-03 to 2024-08-02. */
const SIGNING_CERT_PEM =
    "-----BEGIN CERTIFICATE-----\nMIIDGzCCAgOgAwIBAgIBATANBgkqhkiG9w0BAQsFADBHMSowKAYDVQQKDCFLcmFq\nb3d5IEludGVncmF0b3IgUGxhdG5vc2NpIFMuQS4xGTAXBgNVBAMMEFRwYXkgSldT\nIFJvb3QgQ0EwHhcNMjIwODAzMDYxMzIyWhcNMjQwODAyMDYxMzIyWjBHMSowKAYD\nVQQKDCFLcmFqb3d5IEludGVncmF0b3IgUGxhdG5vc2NpIFMuQS4xGTAXBgNVBAMM\nEG5vdGlmaWNhdGlvbi1qd3MwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB\nAQCzEEHnEktSm5+D/F0a248qw4LC7q+lLPIbV5fo7b9lKpa8KynCA7lK1G+o8H3i\nrdUbWlgaYg+sM6P036bEGlb/Ou68yQ/Km7zfGX/dUk9xIveAwsYq2NYC94cm1md7\nONCzHkGvz2CVZXDv/MV8uaUv7N93g0zF4hDJsA0+i7FNJCL02ulmJW2caXAdIERx\nKJfk3MthKyQprR0/YcUHC9KtFpwD4HBcLPgoprzUv+y9C2DErADmtYiaUUzkEIWP\ncz38AAB5zADDRIwlrmNIrwyZ32xKFlu1lQBIoiGJF6jdtBOjWdRUpH7eQcvM6OaJ\n8/QntqeHovxARp+wuXdV2wSPAgMBAAGjEjAQMA4GA1UdDwEB/wQEAwIHgDANBgkq\nhkiG9w0BAQsFAAOCAQEAvLj3nmPhWeV4dGs4tkMJVaz6HYBBULUWGCyB7GNL1hIh\n2ozxIyESXmdEQ2VIAhKxlE404z4cpQiWAlk9/I9OfvdtiX43KKmi8gYdC3VPtlro\neUFroyY1MHxc6Sq+jfX6jWD6PLpbOf8OfyrapD4NTZm05n1hd8sqA8kuPrhsO5mR\nVLanuTp6S7Q2f+8ix+i2921+QkRuALJ5LlT7wfaoOTQihS5kBqayseblT2dtrSER\nM0mfVnkuMUXFymGLG3a9eBO9Wj/0LqkXA87nl/5DxxsYRNR+UZFSITyyefwmcTBD\nOcxtKLmlcbFJPWQjYkDunPklLj7HwBIeiVEZrAKMjA==\n-----END CERTIFICATE-----\n";

/** Valid from 2022-08-01 to 2032-07-29. */
const ROOT_CERT_PEM =
    "-----BEGIN CERTIFICATE-----\nMIIDNzCCAh+gAwIBAgIJAN3/KXBnrfWpMA0GCSqGSIb3DQEBCwUAMEcxKjAoBgNV\nBAoMIUtyYWpvd3kgSW50ZWdyYXRvciBQbGF0bm9zY2kgUy5BLjEZMBcGA1UEAwwQ\nVHBheSBKV1MgUm9vdCBDQTAeFw0yMjA4MDEwOTA2MzRaFw0zMjA3MjkwOTA2MzRa\nMEcxKjAoBgNVBAoMIUtyYWpvd3kgSW50ZWdyYXRvciBQbGF0bm9zY2kgUy5BLjEZ\nMBcGA1UEAwwQVHBheSBKV1MgUm9vdCBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEP\nADCCAQoCggEBAOtF7BjwpUrtPFQXVnpSV3OwiyLEQR4hvSLBgBglkKpK2MrZnRfe\nz3o4L3O2uSKIEetSiHsMPioOOUdaHcWjgblDTVGXS4LIFp2gaIOHpW/4NBFSPGnz\ngg08dRn4AWwhQeB8R5HHO1WORKKBqyVV47c9HdBCfz3nJcFoX2aVptE70RtpdpSB\nmTp/YFBtkkkwvRZsN8QHeyJQA80KM/oyg3bVatXlXzOF2pVk9qr5RF2TcpRkgeLX\nI6+vPnnDej5NhmHIbjNOYIMKb8WyvwExeO+bI/5wPP0NFV1wF7qw1MwV1gLOP6T1\nikk5z3jTaqhAsdqBL4LHzU3cqXB4p6yksWkCAwEAAaMmMCQwDgYDVR0PAQH/BAQD\nAgLkMBIGA1UdEwEB/wQIMAYBAf8CAQEwDQYJKoZIhvcNAQELBQADggEBAGPUwyHp\nIhUZnbCTAQ9dOk3HpG1Oms3qQrj/i7auqoJgUqdGD4XPb8NkWBG1kVvar0SfIDLZ\nSYz8tPYB8a+hUOGX/F5t4BwbGSvFaHTfBpb28fulSfWLEL4qB1CKGI5sx2aBQN6k\nlhx86pzMfSiuvT8ZfADeL5683tYOQ3nemdcAtMD2NoYVZNvEcaK0lWb023kqsV8r\nTUJfNli3ntuZPE0WXZ0rT0KpgOepd0xSfKBZfAbMzh0GDYkGk3yZBLYgZQGu7xTF\nwFa2xjJ6Lk/1VF+1uFtTCaIRPpH+OZOy7taTiJm36HZcs8mGXmcoyJ3eBqFX1aSC\nZTD4QzypVEzozr0=\n-----END CERTIFICATE-----\n";

const VALID_BODY = Buffer.from(
    "id=123912&tr_id=TR-3HFD-TST24X&tr_date=2024-02-23+07%3A58%3A30&tr_crc=123456789&tr_amount=123.00&tr_paid=123.00&tr_desc=Test+transaction&tr_status=TRUE&tr_error=none&tr_email=user%40example.com&md5sum=4fb89b9bec9974c0e5daf3ad0af7ca1c",
    "utf-8"
);

/** Detached JWS over VALID_BODY, with x5u pointing at SIGNING_CERT_URL. */
const VALID_JWS =
    "eyJhbGciOiJSUzI1NiIsIng1dSI6Imh0dHBzOlwvXC9zZWN1cmUudHBheS5jb21cL3g1MDlcL25vdGlmaWNhdGlvbnMtandzLnBlbSJ9..Xr5042YfUu0C42fdao3pH9TLoAuFL3lgr8f13-PLuIdF0SeZb4AAppcvVeB9cCVclBPh7tgWxrUF3aHxhVxX5tmCU9rVB33KvzeJAdlQ40-kasoWYtEZxX7rdDgcqxQEww_QZlX2r1g8SAhw3o6x0OT0thpyOy817gxRpl7Nk-QrLttx6ks4qJOw1rWXmOqC3_LbS0VswXMPdg-al6rrknhjf755M0WtMWGkrAvwJFhuIfhIjKuISxWdsSrpz6ZeuT1SfOAwlM7DEZtrE7q3Rhu3I9JlTO79a4-HwRLaBoai0tMJjrnPYU5IOXcycF1jAQlQ1BNNfuN9MgWX8AEBGg";

/** The signing certificate is only valid until 2024-08-02, so the clock has to sit inside that window. */
const INSIDE_CERT_VALIDITY = new Date("2024-02-23T07:58:30Z").getTime();

const SIGNING_CERT_VALID_TO = new X509Certificate(SIGNING_CERT_PEM).validToDate.getTime();
const ROOT_CERT_VALID_TO = new X509Certificate(ROOT_CERT_PEM).validToDate.getTime();

function jwsWithX5u(x5u: string): string {
    const header = Buffer.from(JSON.stringify({ alg: "RS256", x5u }), "utf8").toString("base64url");
    return `${header}..AAAA`;
}

/** Serves the same certificate for every '/x509/' path, so that bogus x5u URLs still produce a chaining certificate. */
function serveAnySigningCertUrl(fetchMock: jest.Mock): void {
    fetchMock.mockImplementation(async (url: string) => {
        const pem = url === ROOT_CERT_URL ? ROOT_CERT_PEM : SIGNING_CERT_PEM;
        return { ok: true, headers: new Headers(), text: async () => pem };
    });
}

describe("TpayWebhookAuth", () => {
    let tpayWebhookAuth: TpayWebhookAuth;
    let fetchMock: jest.Mock;

    beforeEach(() => {
        jest.spyOn(Date, "now").mockReturnValue(INSIDE_CERT_VALIDITY);

        fetchMock = jest.fn().mockImplementation(async (url: string) => {
            if (url === SIGNING_CERT_URL) {
                return { ok: true, headers: new Headers(), text: async () => SIGNING_CERT_PEM };
            }
            if (url === ROOT_CERT_URL) {
                return { ok: true, headers: new Headers(), text: async () => ROOT_CERT_PEM };
            }

            throw new Error(`Unexpected fetch of '${url}'`);
        });
        jest.spyOn(global, "fetch").mockImplementation(fetchMock);

        tpayWebhookAuth = new TpayWebhookAuth({ sandboxMode: false });
    });

    afterEach(() => {
        jest.restoreAllMocks();
    });

    it("should return true if the signature is valid", async () => {
        const result = await tpayWebhookAuth.checkSignature(VALID_BODY, VALID_JWS);

        expect(result).toBe(true);
    });

    it("should return false if the signature does not match the body", async () => {
        const result = await tpayWebhookAuth.checkSignature(Buffer.from("id=123912", "utf-8"), VALID_JWS);

        expect(result).toBe(false);
    });

    describe("x5u URL validation", () => {
        const untrustedUrls = [
            "https://secure.tpay.com.example.com/x509/notifications-jws.pem",
            "https://secure.tpay.com@example.com/x509/notifications-jws.pem",
            "https://secure.sandbox.tpay.com/x509/notifications-jws.pem",
            "http://secure.tpay.com/x509/notifications-jws.pem",
            "https://secure.tpay.com/../etc/passwd",
            "https://secure.tpay.com/x509/notifications-jws.pem?v=1",
            "https://secure.tpay.com/x509/notifications-jws.pem#v1",
        ];

        it.each(untrustedUrls)("should reject the x5u URL '%s' without fetching it", async (url) => {
            await expect(tpayWebhookAuth.checkSignature(VALID_BODY, jwsWithX5u(url))).rejects.toThrow(/Unexpected x5u URL/);

            expect(fetchMock).not.toHaveBeenCalled();
        });

        it("should accept the expected origin", async () => {
            const result = await tpayWebhookAuth.checkSignature(VALID_BODY, VALID_JWS);

            expect(result).toBe(true);
            expect(fetchMock).toHaveBeenCalledWith(SIGNING_CERT_URL, expect.objectContaining({ redirect: "error" }));
        });

        it("should use the sandbox origin when sandboxMode is enabled", async () => {
            const sandboxAuth = new TpayWebhookAuth({ sandboxMode: true });

            await expect(sandboxAuth.checkSignature(VALID_BODY, VALID_JWS)).rejects.toThrow(/Unexpected x5u URL/);
        });
    });

    describe("certificate validity period", () => {
        it("should reject an expired signing certificate", async () => {
            jest.spyOn(Date, "now").mockReturnValue(new Date("2025-01-01T00:00:00Z").getTime());

            await expect(tpayWebhookAuth.checkSignature(VALID_BODY, VALID_JWS)).rejects.toThrow(/Signing certificate expired/);
        });

        it("should reject a signing certificate that is not valid yet", async () => {
            jest.spyOn(Date, "now").mockReturnValue(new Date("2022-01-01T00:00:00Z").getTime());

            await expect(tpayWebhookAuth.checkSignature(VALID_BODY, VALID_JWS)).rejects.toThrow(/Signing certificate is not valid yet/);
        });

        it("should not cache a signing certificate past its own expiry", async () => {
            jest.spyOn(Date, "now").mockReturnValue(SIGNING_CERT_VALID_TO - 10 * 60 * 1000);

            await tpayWebhookAuth.checkSignature(VALID_BODY, VALID_JWS);

            // The 1h TTL would otherwise outlive the certificate by 50 minutes.
            expect(tpayWebhookAuth["cachedSigningCerts"].get(SIGNING_CERT_URL)?.expiresAt).toBe(SIGNING_CERT_VALID_TO);
        });

        it("should refetch a signing certificate that expired while cached, rather than serving it", async () => {
            jest.spyOn(Date, "now").mockReturnValue(SIGNING_CERT_VALID_TO - 10 * 60 * 1000);
            expect(await tpayWebhookAuth.checkSignature(VALID_BODY, VALID_JWS)).toBe(true);

            // 20 minutes later the certificate has expired but the TTL has not. Tpay rotates in place, so the only
            // useful thing to do is go back to the network. Here the mock keeps serving the expired certificate, so
            // the request is still rejected, but the second fetch proves the cache did not decide that on its own.
            jest.spyOn(Date, "now").mockReturnValue(SIGNING_CERT_VALID_TO + 10 * 60 * 1000);
            await expect(tpayWebhookAuth.checkSignature(VALID_BODY, VALID_JWS)).rejects.toThrow(/Signing certificate expired/);

            expect(fetchMock.mock.calls.filter(([url]) => url === SIGNING_CERT_URL)).toHaveLength(2);
        });

        it("should not cache the root certificate past its own expiry", async () => {
            jest.spyOn(Date, "now").mockReturnValue(ROOT_CERT_VALID_TO - 10 * 60 * 1000);

            await tpayWebhookAuth["refetchRootCert"]();

            expect(tpayWebhookAuth["cachedRootCert"]?.expiresAt).toBe(ROOT_CERT_VALID_TO);
        });
    });

    describe("root certificate", () => {
        function seedCachedRootCert(pem: string): void {
            tpayWebhookAuth["cachedRootCert"] = { cert: new X509Certificate(pem), expiresAt: Date.now() + 60_000 };
        }

        function rootCertFetchCount(): number {
            return fetchMock.mock.calls.filter(([url]) => url === ROOT_CERT_URL).length;
        }

        // Pairs with the test below: a seeded root that still matches must not be refetched. Without this, the
        // rotation test would pass even if seeding the cache silently did nothing.
        it("should trust a cached root certificate that still matches", async () => {
            seedCachedRootCert(ROOT_CERT_PEM);

            const result = await tpayWebhookAuth.checkSignature(VALID_BODY, VALID_JWS);

            expect(result).toBe(true);
            expect(rootCertFetchCount()).toBe(0);
        });

        it("should recover when the cached root certificate no longer matches", async () => {
            // Seed the cache with a certificate that did not sign the signing cert, as if Tpay had rotated the root.
            // The fix for the fall-through bug is what lets the refetched root be used instead of throwing outright.
            seedCachedRootCert(SIGNING_CERT_PEM);

            const result = await tpayWebhookAuth.checkSignature(VALID_BODY, VALID_JWS);

            expect(result).toBe(true);
            expect(rootCertFetchCount()).toBe(1);
            expect(tpayWebhookAuth["cachedRootCert"]?.cert.subject).toContain("Tpay JWS Root CA");
        });

        it("should throw when the signing certificate does not chain to the refetched root", async () => {
            // Serve the signing certificate as the root, so the chain check cannot succeed.
            fetchMock.mockImplementation(async () => ({ ok: true, headers: new Headers(), text: async () => SIGNING_CERT_PEM }));

            await expect(tpayWebhookAuth.checkSignature(VALID_BODY, VALID_JWS)).rejects.toThrow(
                "Signing certificate is not signed by Tpay CA certificate."
            );
        });

        it("should not refetch the root certificate on every request", async () => {
            await tpayWebhookAuth.checkSignature(VALID_BODY, VALID_JWS);
            await tpayWebhookAuth.checkSignature(VALID_BODY, VALID_JWS);

            expect(fetchMock.mock.calls.filter(([url]) => url === ROOT_CERT_URL)).toHaveLength(1);
        });

        it("should refetch the root certificate once its TTL expires", async () => {
            await tpayWebhookAuth.checkSignature(VALID_BODY, VALID_JWS);

            jest.spyOn(Date, "now").mockReturnValue(INSIDE_CERT_VALIDITY + 2 * 60 * 60 * 1000);
            await tpayWebhookAuth.checkSignature(VALID_BODY, VALID_JWS);

            expect(fetchMock.mock.calls.filter(([url]) => url === ROOT_CERT_URL)).toHaveLength(2);
        });
    });

    describe("signing certificate cache", () => {
        it("should not refetch the signing certificate on every request", async () => {
            await tpayWebhookAuth.checkSignature(VALID_BODY, VALID_JWS);
            await tpayWebhookAuth.checkSignature(VALID_BODY, VALID_JWS);

            expect(fetchMock.mock.calls.filter(([url]) => url === SIGNING_CERT_URL)).toHaveLength(1);
        });

        it("should stay bounded when many distinct x5u URLs are used", async () => {
            // The cache is populated before the signature itself is checked, so invalid requests land here too.
            serveAnySigningCertUrl(fetchMock);

            for (let i = 0; i < 200; i++) {
                const result = await tpayWebhookAuth.checkSignature(VALID_BODY, jwsWithX5u(`https://secure.tpay.com/x509/cert-${i}.pem`));
                expect(result).toBe(false);
            }

            expect(tpayWebhookAuth["cachedSigningCerts"].size).toBe(16);
        });

        it("should keep the certificate in use when unknown x5u URLs flood the cache", async () => {
            serveAnySigningCertUrl(fetchMock);

            async function floodWithUnknownUrls(from: number, count: number): Promise<void> {
                for (let i = from; i < from + count; i++) {
                    await tpayWebhookAuth.checkSignature(VALID_BODY, jwsWithX5u(`https://secure.tpay.com/x509/cert-${i}.pem`));
                }
            }

            await tpayWebhookAuth.checkSignature(VALID_BODY, VALID_JWS);
            await floodWithUnknownUrls(0, 15); // Fills the cache without evicting anything.
            await tpayWebhookAuth.checkSignature(VALID_BODY, VALID_JWS); // A hit, so the real certificate is no longer the oldest.
            await floodWithUnknownUrls(15, 5); // Evicts the least recently used entries, which are now the bogus ones.

            expect(tpayWebhookAuth["cachedSigningCerts"].has(SIGNING_CERT_URL)).toBe(true);
            expect(fetchMock.mock.calls.filter(([url]) => url === SIGNING_CERT_URL)).toHaveLength(1);
        });
    });

    describe("concurrent requests", () => {
        it("should download each certificate once", async () => {
            const results = await Promise.all([
                tpayWebhookAuth.checkSignature(VALID_BODY, VALID_JWS),
                tpayWebhookAuth.checkSignature(VALID_BODY, VALID_JWS),
                tpayWebhookAuth.checkSignature(VALID_BODY, VALID_JWS),
            ]);

            expect(results).toEqual([true, true, true]);
            expect(fetchMock.mock.calls.filter(([url]) => url === SIGNING_CERT_URL)).toHaveLength(1);
            expect(fetchMock.mock.calls.filter(([url]) => url === ROOT_CERT_URL)).toHaveLength(1);
        });

        it("should not hold on to a failed download", async () => {
            fetchMock.mockImplementationOnce(async () => ({ ok: false, status: 503, headers: new Headers() }));

            await expect(tpayWebhookAuth.checkSignature(VALID_BODY, VALID_JWS)).rejects.toThrow(/Failed to fetch certificate/);
            expect(await tpayWebhookAuth.checkSignature(VALID_BODY, VALID_JWS)).toBe(true);
        });
    });

    describe("malformed input", () => {
        it.each([
            ["a JWS with too few segments", `${VALID_JWS.split(".")[0]}.${VALID_JWS.split(".")[2]}`],
            ["a JWS with too many segments", `${VALID_JWS}.extra`],
        ])("should reject %s", async (_name, jws) => {
            await expect(tpayWebhookAuth.checkSignature(VALID_BODY, jws)).rejects.toThrow(/Expected 3 dot-separated segments/);
        });

        it("should reject a non-empty payload segment even when the signature is otherwise valid", async () => {
            const [header, , signature] = VALID_JWS.split(".");

            // Tpay sends a detached JWS, so the payload segment is always empty. Verification ignores it, which is
            // exactly why a stray payload must be rejected rather than quietly waved through as authentic.
            await expect(tpayWebhookAuth.checkSignature(VALID_BODY, `${header}.cGF5bG9hZA.${signature}`)).rejects.toThrow(
                "Invalid signature format. The payload segment must be empty."
            );
        });

        it("should reject a header with an unexpected 'alg'", async () => {
            const header = Buffer.from(JSON.stringify({ alg: "none", x5u: SIGNING_CERT_URL }), "utf8").toString("base64url");

            await expect(tpayWebhookAuth.checkSignature(VALID_BODY, `${header}..AAAA`)).rejects.toThrow(
                "Invalid signature format. Expected the 'alg' field to be 'RS256'."
            );
            expect(fetchMock).not.toHaveBeenCalled();
        });

        it("should reject a header that is not a JSON object", async () => {
            const header = Buffer.from(JSON.stringify("RS256"), "utf8").toString("base64url");

            await expect(tpayWebhookAuth.checkSignature(VALID_BODY, `${header}..AAAA`)).rejects.toThrow(
                "Invalid signature format. Header is not a JSON object."
            );
        });

        it("should reject a header that is not valid JSON", async () => {
            const header = Buffer.from("not json", "utf8").toString("base64url");

            await expect(tpayWebhookAuth.checkSignature(VALID_BODY, `${header}..AAAA`)).rejects.toThrow(
                "Invalid signature format. Header is not valid JSON."
            );
        });

        it("should reject a header without an x5u field", async () => {
            const header = Buffer.from(JSON.stringify({ alg: "RS256" }), "utf8").toString("base64url");

            await expect(tpayWebhookAuth.checkSignature(VALID_BODY, `${header}..AAAA`)).rejects.toThrow(/missing the 'x5u' field/);
        });
    });
});
