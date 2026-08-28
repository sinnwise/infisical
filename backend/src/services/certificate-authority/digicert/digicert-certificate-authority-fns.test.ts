import { beforeEach, describe, expect, it, vi } from "vitest";

import { CertKeyAlgorithm } from "@app/services/certificate/certificate-types";

import { CaStatus, CaType } from "../certificate-authority-enums";
import { createDigiCertApiClient } from "./digicert-api-client";
import { DigiCertCertificateAuthorityFns } from "./digicert-certificate-authority-fns";
import { DigiCertCaPurpose, DigiCertDcvScope } from "./digicert-certificate-authority-schemas";
import {
  castDbEntryToDigiCertCertificateAuthority,
  getDigiCertClientCredentials
} from "./digicert-certificate-authority-shared";

vi.mock("./digicert-api-client", () => ({ createDigiCertApiClient: vi.fn() }));
vi.mock("./digicert-certificate-authority-shared", () => ({
  castDbEntryToDigiCertCertificateAuthority: vi.fn(),
  extractLeafAndChain: vi.fn(),
  getDigiCertClientCredentials: vi.fn()
}));

const BARE_CSR = `-----BEGIN CERTIFICATE REQUEST-----
MIICjjCCAXYCAQAwGzEZMBcGA1UEAwwQc2hvcC5leGFtcGxlLmNvbTCCASIwDQYJ
KoZIhvcNAQEBBQADggEPADCCAQoCggEBAOVJz54yKwVJUNUxxj3zYEO+KO86+DCB
0oUgIZE57FBAhadTkXjmorF2VMtdAhMo2whNBY1JxSwJsaXTkYKAV0wkryFoG0x3
9qElqH7+5ckPjltZqLKeQoE8v6ziTmi/wzYZJJ3hAlzP2UNWo5SzdjSUYTNDln+Z
NJh6GIpQfebYL5YF9errqmr6eRNQcQJVKq5awKSlnb0AzXkDXKsXgpLkDa83obSW
mPPQlYMbwq/kDY2373rVDFsIqt+K0yYbxsxZuNttibF3MS4GlVvcwL7uLqxrMeiy
9dqKypXFXF+R0LLo6BpGeyLqhVQDQ9BdP2LFmTSBoIw80gCi2VN4U30CAwEAAaAu
MCwGCSqGSIb3DQEJDjEfMB0wGwYDVR0RBBQwEoIQc2hvcC5leGFtcGxlLmNvbTAN
BgkqhkiG9w0BAQsFAAOCAQEAj/NR+XynMXEl6/Hmm8KLh1K1mtQXzLdNT5Xb6DKF
HR0HlkT+nNfrXbECGuu0ZieEla/b9DUzavm0MMSizEdyKfqfIZ6CrBl3JI5EVmSr
1ipzQ0eEZpOZm9W8NqCr1dizjL+kx7LfvF//ginhPi8Z0DR0SEmcHQLHAOjEAicB
K7ZGYcMkNXRQQNAUvxCmPAWKc/hU0FBEZCn+mriYXMwGDisnYPMUf57dRD60aZ/l
teiHSBQxLjT2dAkV6JFsed1JZXWLHN4FoBAEPljijBDl0ROJM7Lfr6NcNBcpI5I0
ER5rq/0lkFde5xjkJFX9i6sVEksCRgegDVjbCZfQ+XL+Mw==
-----END CERTIFICATE REQUEST-----`;

const CN_ONLY_CSR = `-----BEGIN CERTIFICATE REQUEST-----
MIICYDCCAUgCAQAwGzEZMBcGA1UEAwwQb25seS5leGFtcGxlLmNvbTCCASIwDQYJ
KoZIhvcNAQEBBQADggEPADCCAQoCggEBANXOjXdpeNuGT/92BqtJ0dttFrF6hzYh
HDcMAsSO7lJt0CHBxIHD7VI8rIrI0SSzGwvt/9h6G4J7aTT8XvOVyj/e9yLO2keG
1O++LJa1qnZlkHAlSvQgNWU1t0ZaPn7o1qxaWPnPWfM2BkS41m9sJmbWDVr3kt/I
9wcTjg4VCaRoDhSCSOWS3f1omWrHKUwxzvRuVgvaRMKED5IIUguW7qjmBbP15+zj
nYNVV9pG0uOwD1pYtSJ6qg7/75JDWHhiiKFgzas5Vljv1xvw5kDTqWBeJwWEEFmJ
oO6fVIBQzpabxs+AzIY1G4LwTfMgUgLUVClZP5cxYjTXe33AzFqw5A0CAwEAAaAA
MA0GCSqGSIb3DQEBCwUAA4IBAQA3Y/hK5xq0qp7D+QK2IBmHzRrwf3/Vcn5dFAn/
mqftdLXFVi71XejEueKy3+kwv6cWTRT5+/okYAY1ktrFlCzy2qGjGCEURDKo2/xx
n7DobFkMJOL3qZ6ctIk80ziIYjWeVd/Q9MBOhCHfK/2MD8/EFJhUaetBvmUZtY6q
IZTBXoyLMGHGnvHgYgDhERGZ35Ceu9iqa48N+oUWPYdDCdKPn+ac88funeev0eeF
p+sM1HK6NpP71LI13gie2NZhkqVBHkTpNV9LGB/p8vC3EhCR9RvKMWqFiHXAwekQ
beojaxiivUv31AOWONQGT6UNADIYR/+T6YXY5x+YaRh9Frgl
-----END CERTIFICATE REQUEST-----`;

type TX9OrderPayload = {
  certificate: {
    common_name: string;
    dns_names?: string[];
    csr: string;
    signature_hash: string;
    key_usages?: string[];
    extended_key_usages?: string[];
  };
  organization: { id: number };
  order_validity: { days: number };
  dcv_method: string;
  certificate_dcv_scope?: string;
  skip_approval: boolean;
};

const createService = () => {
  const placeOrder = vi.fn<(productNameId: string, payload: TX9OrderPayload) => Promise<{ id: number }>>();
  placeOrder.mockResolvedValue({ id: 123 });
  const findByIdWithAssociatedCa = vi.fn().mockResolvedValue({
    id: "ca-id",
    externalCa: { type: CaType.DIGICERT }
  });

  vi.mocked(castDbEntryToDigiCertCertificateAuthority).mockReturnValue({
    id: "ca-id",
    type: CaType.DIGICERT,
    enableDirectIssuance: false,
    name: "digicert-x9",
    projectId: "project-id",
    credentials: null,
    status: CaStatus.ACTIVE,
    configuration: {
      appConnectionId: "connection-id",
      organizationId: 123,
      productNameId: "x9_pki",
      purpose: DigiCertCaPurpose.X9Pki,
      certificateDcvScope: DigiCertDcvScope.Fqdn
    }
  } as never);
  vi.mocked(getDigiCertClientCredentials).mockResolvedValue({ apiKey: "api-key", baseUrl: "https://example.com" });
  vi.mocked(createDigiCertApiClient).mockReturnValue({ placeOrder } as never);

  const service = DigiCertCertificateAuthorityFns({
    appConnectionDAL: {},
    appConnectionService: {},
    certificateAuthorityDAL: { findByIdWithAssociatedCa },
    externalCertificateAuthorityDAL: {},
    certificateDAL: {},
    certificateBodyDAL: {},
    certificateSecretDAL: {},
    kmsService: {},
    projectDAL: {}
  } as never);

  return { service, placeOrder };
};

describe("DigiCertCertificateAuthorityFns.orderCertificate", () => {
  beforeEach(() => vi.clearAllMocks());

  it("uses X9 identities and key details from a supplied CSR", async () => {
    const { service, placeOrder } = createService();

    await service.orderCertificate({
      caId: "ca-id",
      commonName: "ignored.example.com",
      altNames: ["ignored.example.com"],
      csr: BARE_CSR,
      keyAlgorithm: CertKeyAlgorithm.ECDSA_P521,
      keyUsages: ["digitalSignature"],
      extendedKeyUsages: ["serverAuth"],
      ttl: "30d"
    });

    expect(placeOrder).toHaveBeenCalledWith("x9_pki", {
      certificate: {
        common_name: "shop.example.com",
        csr: BARE_CSR,
        signature_hash: "sha256",
        key_usages: ["digital_signature"],
        extended_key_usages: ["server_authentication"]
      },
      organization: { id: 123 },
      order_validity: { days: 30 },
      dcv_method: "dns-txt-token",
      certificate_dcv_scope: "fqdn",
      skip_approval: true
    });
  });

  it("uses request SANs when a supplied X9 CSR has none", async () => {
    const { service, placeOrder } = createService();

    await service.orderCertificate({
      caId: "ca-id",
      commonName: "ignored.example.com",
      altNames: ["api.example.com"],
      csr: CN_ONLY_CSR,
      ttl: "30d"
    });

    const [, payload] = placeOrder.mock.calls[0];
    expect(payload.certificate.common_name).toBe("only.example.com");
    expect(payload.certificate.dns_names).toEqual(["api.example.com"]);
  });

  it("sends IP SANs through the X9 order payload with HTTP validation", async () => {
    const { service, placeOrder } = createService();

    await service.orderCertificate({
      caId: "ca-id",
      commonName: "api.example.com",
      altNames: ["1.1.1.1"],
      keyAlgorithm: CertKeyAlgorithm.RSA_2048,
      ttl: "30d"
    });

    expect(placeOrder).toHaveBeenCalledOnce();
    const [productNameId, payload] = placeOrder.mock.calls[0];
    expect(productNameId).toBe("x9_pki");
    expect(payload).toMatchObject({
      certificate: {
        common_name: "api.example.com",
        dns_names: ["1.1.1.1"]
      },
      dcv_method: "http-token",
      certificate_dcv_scope: "fqdn"
    });
    expect(payload.certificate.csr).toContain("BEGIN CERTIFICATE REQUEST");
  });

  it("uses the curve-matched signature hash for generated ECC CSRs", async () => {
    const { service, placeOrder } = createService();

    await service.orderCertificate({
      caId: "ca-id",
      commonName: "api.example.com",
      keyAlgorithm: CertKeyAlgorithm.ECDSA_P384,
      signatureAlgorithm: "ECDSA-SHA256",
      ttl: "30d"
    });

    const [, payload] = placeOrder.mock.calls[0];
    expect(payload.certificate.signature_hash).toBe("sha384");
  });

  it("uses SHA-512 for generated RSA X9 certificates", async () => {
    const { service, placeOrder } = createService();

    await service.orderCertificate({
      caId: "ca-id",
      commonName: "api.example.com",
      keyAlgorithm: CertKeyAlgorithm.RSA_4096,
      signatureAlgorithm: "RSA-SHA512",
      ttl: "30d"
    });

    const [, payload] = placeOrder.mock.calls[0];
    expect(payload.certificate.signature_hash).toBe("sha512");
  });

  it("rejects unsupported X9 key algorithms before placing an order", async () => {
    const { service, placeOrder } = createService();

    await expect(
      service.orderCertificate({
        caId: "ca-id",
        commonName: "api.example.com",
        keyAlgorithm: CertKeyAlgorithm.ECDSA_P521,
        ttl: "30d"
      })
    ).rejects.toThrow("supports RSA_2048");

    expect(placeOrder).not.toHaveBeenCalled();
  });
});
