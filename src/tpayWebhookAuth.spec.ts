import { TpayWebhookAuth } from "./tpayWebhookAuth";

describe("TpayWebhookAuth", () => {
    const tpayWebhookAuth = new TpayWebhookAuth({ sandboxMode: false });

    beforeAll(() => {
        const fetchMock = jest.fn().mockImplementation(async (url: string) => {
            // mock x5u response
            if (url === "https://secure.tpay.com/x509/notifications-jws.pem") {
                return {
                    ok: true,
                    text: jest
                        .fn()
                        .mockResolvedValue(
                            "-----BEGIN CERTIFICATE-----\nMIIDGzCCAgOgAwIBAgIBATANBgkqhkiG9w0BAQsFADBHMSowKAYDVQQKDCFLcmFq\nb3d5IEludGVncmF0b3IgUGxhdG5vc2NpIFMuQS4xGTAXBgNVBAMMEFRwYXkgSldT\nIFJvb3QgQ0EwHhcNMjIwODAzMDYxMzIyWhcNMjQwODAyMDYxMzIyWjBHMSowKAYD\nVQQKDCFLcmFqb3d5IEludGVncmF0b3IgUGxhdG5vc2NpIFMuQS4xGTAXBgNVBAMM\nEG5vdGlmaWNhdGlvbi1qd3MwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB\nAQCzEEHnEktSm5+D/F0a248qw4LC7q+lLPIbV5fo7b9lKpa8KynCA7lK1G+o8H3i\nrdUbWlgaYg+sM6P036bEGlb/Ou68yQ/Km7zfGX/dUk9xIveAwsYq2NYC94cm1md7\nONCzHkGvz2CVZXDv/MV8uaUv7N93g0zF4hDJsA0+i7FNJCL02ulmJW2caXAdIERx\nKJfk3MthKyQprR0/YcUHC9KtFpwD4HBcLPgoprzUv+y9C2DErADmtYiaUUzkEIWP\ncz38AAB5zADDRIwlrmNIrwyZ32xKFlu1lQBIoiGJF6jdtBOjWdRUpH7eQcvM6OaJ\n8/QntqeHovxARp+wuXdV2wSPAgMBAAGjEjAQMA4GA1UdDwEB/wQEAwIHgDANBgkq\nhkiG9w0BAQsFAAOCAQEAvLj3nmPhWeV4dGs4tkMJVaz6HYBBULUWGCyB7GNL1hIh\n2ozxIyESXmdEQ2VIAhKxlE404z4cpQiWAlk9/I9OfvdtiX43KKmi8gYdC3VPtlro\neUFroyY1MHxc6Sq+jfX6jWD6PLpbOf8OfyrapD4NTZm05n1hd8sqA8kuPrhsO5mR\nVLanuTp6S7Q2f+8ix+i2921+QkRuALJ5LlT7wfaoOTQihS5kBqayseblT2dtrSER\nM0mfVnkuMUXFymGLG3a9eBO9Wj/0LqkXA87nl/5DxxsYRNR+UZFSITyyefwmcTBD\nOcxtKLmlcbFJPWQjYkDunPklLj7HwBIeiVEZrAKMjA==\n-----END CERTIFICATE-----\n"
                        ),
                };
            }

            // mock root cert response
            if (url === "https://secure.tpay.com/x509/tpay-jws-root.pem") {
                return {
                    ok: true,
                    text: jest
                        .fn()
                        .mockResolvedValue(
                            "-----BEGIN CERTIFICATE-----\nMIIDNzCCAh+gAwIBAgIJAN3/KXBnrfWpMA0GCSqGSIb3DQEBCwUAMEcxKjAoBgNV\nBAoMIUtyYWpvd3kgSW50ZWdyYXRvciBQbGF0bm9zY2kgUy5BLjEZMBcGA1UEAwwQ\nVHBheSBKV1MgUm9vdCBDQTAeFw0yMjA4MDEwOTA2MzRaFw0zMjA3MjkwOTA2MzRa\nMEcxKjAoBgNVBAoMIUtyYWpvd3kgSW50ZWdyYXRvciBQbGF0bm9zY2kgUy5BLjEZ\nMBcGA1UEAwwQVHBheSBKV1MgUm9vdCBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEP\nADCCAQoCggEBAOtF7BjwpUrtPFQXVnpSV3OwiyLEQR4hvSLBgBglkKpK2MrZnRfe\nz3o4L3O2uSKIEetSiHsMPioOOUdaHcWjgblDTVGXS4LIFp2gaIOHpW/4NBFSPGnz\ngg08dRn4AWwhQeB8R5HHO1WORKKBqyVV47c9HdBCfz3nJcFoX2aVptE70RtpdpSB\nmTp/YFBtkkkwvRZsN8QHeyJQA80KM/oyg3bVatXlXzOF2pVk9qr5RF2TcpRkgeLX\nI6+vPnnDej5NhmHIbjNOYIMKb8WyvwExeO+bI/5wPP0NFV1wF7qw1MwV1gLOP6T1\nikk5z3jTaqhAsdqBL4LHzU3cqXB4p6yksWkCAwEAAaMmMCQwDgYDVR0PAQH/BAQD\nAgLkMBIGA1UdEwEB/wQIMAYBAf8CAQEwDQYJKoZIhvcNAQELBQADggEBAGPUwyHp\nIhUZnbCTAQ9dOk3HpG1Oms3qQrj/i7auqoJgUqdGD4XPb8NkWBG1kVvar0SfIDLZ\nSYz8tPYB8a+hUOGX/F5t4BwbGSvFaHTfBpb28fulSfWLEL4qB1CKGI5sx2aBQN6k\nlhx86pzMfSiuvT8ZfADeL5683tYOQ3nemdcAtMD2NoYVZNvEcaK0lWb023kqsV8r\nTUJfNli3ntuZPE0WXZ0rT0KpgOepd0xSfKBZfAbMzh0GDYkGk3yZBLYgZQGu7xTF\nwFa2xjJ6Lk/1VF+1uFtTCaIRPpH+OZOy7taTiJm36HZcs8mGXmcoyJ3eBqFX1aSC\nZTD4QzypVEzozr0=\n-----END CERTIFICATE-----\n"
                        ),
                };
            }

            throw new Error("Invalid URL");
        });
        jest.spyOn(global, "fetch").mockImplementation(fetchMock);
    });

    it("should return true if the signature is valid", async () => {
        const body = Buffer.from(
            "id=123912&tr_id=TR-3HFD-TST24X&tr_date=2024-02-23+07%3A58%3A30&tr_crc=123456789&tr_amount=123.00&tr_paid=123.00&tr_desc=Test+transaction&tr_status=TRUE&tr_error=none&tr_email=user%40example.com&md5sum=4fb89b9bec9974c0e5daf3ad0af7ca1c",
            "utf-8"
        );
        const jwsSignature =
            "eyJhbGciOiJSUzI1NiIsIng1dSI6Imh0dHBzOlwvXC9zZWN1cmUudHBheS5jb21cL3g1MDlcL25vdGlmaWNhdGlvbnMtandzLnBlbSJ9..Xr5042YfUu0C42fdao3pH9TLoAuFL3lgr8f13-PLuIdF0SeZb4AAppcvVeB9cCVclBPh7tgWxrUF3aHxhVxX5tmCU9rVB33KvzeJAdlQ40-kasoWYtEZxX7rdDgcqxQEww_QZlX2r1g8SAhw3o6x0OT0thpyOy817gxRpl7Nk-QrLttx6ks4qJOw1rWXmOqC3_LbS0VswXMPdg-al6rrknhjf755M0WtMWGkrAvwJFhuIfhIjKuISxWdsSrpz6ZeuT1SfOAwlM7DEZtrE7q3Rhu3I9JlTO79a4-HwRLaBoai0tMJjrnPYU5IOXcycF1jAQlQ1BNNfuN9MgWX8AEBGg";

        const result = await tpayWebhookAuth.checkSignature(body, jwsSignature);

        expect(result).toBe(true);
    });

    it("should return false if the signature is valid", async () => {
        const body = Buffer.from("id=123912", "utf-8");
        const jwsSignature =
            "eyJhbGciOiJSUzI1NiIsIng1dSI6Imh0dHBzOlwvXC9zZWN1cmUudHBheS5jb21cL3g1MDlcL25vdGlmaWNhdGlvbnMtandzLnBlbSJ9..Xr5042YfUu0C42fdao3pH9TLoAuFL3lgr8f13-PLuIdF0SeZb4AAppcvVeB9cCVclBPh7tgWxrUF3aHxhVxX5tmCU9rVB33KvzeJAdlQ40-kasoWYtEZxX7rdDgcqxQEww_QZlX2r1g8SAhw3o6x0OT0thpyOy817gxRpl7Nk-QrLttx6ks4qJOw1rWXmOqC3_LbS0VswXMPdg-al6rrknhjf755M0WtMWGkrAvwJFhuIfhIjKuISxWdsSrpz6ZeuT1SfOAwlM7DEZtrE7q3Rhu3I9JlTO79a4-HwRLaBoai0tMJjrnPYU5IOXcycF1jAQlQ1BNNfuN9MgWX8AEBGg";

        const result = await tpayWebhookAuth.checkSignature(body, jwsSignature);

        expect(result).toBe(false);
    });
});
