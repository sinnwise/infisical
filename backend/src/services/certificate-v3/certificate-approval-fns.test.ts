import { describe, expect, it, vi } from "vitest";

import { CaType } from "@app/services/certificate-authority/certificate-authority-enums";
import { CertificateRequestStatus } from "@app/services/certificate-request/certificate-request-types";

import {
  certificateApprovalServiceFactory,
  TIssueCertificateFromApprovedRequestDeps
} from "./certificate-approval-fns";

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

const createService = (
  csr: string | null,
  keyAlgorithm = "RSA_2048",
  signatureAlgorithm = "RSA-SHA256",
  {
    defaults = null,
    keyUsages = [],
    extendedKeyUsages = []
  }: {
    defaults?: {
      keyAlgorithm?: string;
      signatureAlgorithm?: string;
      keyUsages?: string[];
      extendedKeyUsages?: string[];
    } | null;
    keyUsages?: string[] | null;
    extendedKeyUsages?: string[] | null;
  } = {}
) => {
  const queueCertificateIssuance = vi.fn().mockResolvedValue(undefined);
  const signCertFromCa = vi.fn();
  const issueCertFromCa = vi.fn();

  const service = certificateApprovalServiceFactory({
    certificateRequestDAL: {
      findById: vi.fn().mockResolvedValue({
        id: "request-id",
        status: CertificateRequestStatus.PENDING,
        profileId: "profile-id",
        csr,
        commonName: "shop.example.com",
        altNames: [],
        keyUsages,
        extendedKeyUsages,
        keyAlgorithm,
        signatureAlgorithm,
        ttl: "30d",
        basicConstraints: null,
        organization: null,
        organizationalUnit: null,
        country: null,
        state: null,
        locality: null,
        notBefore: null,
        notAfter: null,
        applicationId: null
      }),
      updateById: vi.fn().mockResolvedValue(undefined)
    },
    certificateProfileDAL: {
      findByIdWithConfigs: vi.fn().mockResolvedValue({
        id: "profile-id",
        projectId: "project-id",
        caId: "ca-id",
        certificatePolicyId: "policy-id",
        defaults,
        slug: "digicert-profile"
      })
    },
    certificateAuthorityDAL: {
      findByIdWithAssociatedCa: vi.fn().mockResolvedValue({
        id: "ca-id",
        projectId: "project-id",
        externalCa: { type: CaType.DIGICERT, configuration: { productNameId: "x9_pki" } }
      })
    },
    certificatePolicyService: {
      validateCertificateRequest: vi.fn().mockResolvedValue({ isValid: true, errors: [] })
    },
    certificateIssuanceQueue: { queueCertificateIssuance },
    internalCaService: { signCertFromCa, issueCertFromCa }
  } as unknown as TIssueCertificateFromApprovedRequestDeps);

  return { service, queueCertificateIssuance, signCertFromCa, issueCertFromCa };
};

describe("certificateApprovalServiceFactory", () => {
  it.each([
    ["without a CSR", null],
    ["with a CSR", BARE_CSR]
  ])("queues approved DigiCert requests %s", async (_description, csr) => {
    const { service, queueCertificateIssuance, signCertFromCa, issueCertFromCa } = createService(csr);

    const result = await service.issueCertificate("request-id");

    expect(result.status).toBe(CertificateRequestStatus.PENDING);
    expect(queueCertificateIssuance).toHaveBeenCalledWith(
      expect.objectContaining({
        caId: "ca-id",
        caType: CaType.DIGICERT,
        certificateRequestId: "request-id"
      })
    );
    expect(signCertFromCa).not.toHaveBeenCalled();
    expect(issueCertFromCa).not.toHaveBeenCalled();
  });

  it("rejects unsupported X9 requests before queueing", async () => {
    const { service, queueCertificateIssuance } = createService(null, "EC_secp521r1");

    await expect(service.issueCertificate("request-id")).rejects.toThrow("supports RSA_2048");

    expect(queueCertificateIssuance).not.toHaveBeenCalled();
  });

  it("uses profile defaults when queueing approved X9 requests", async () => {
    const { service, queueCertificateIssuance } = createService(null, "", "", {
      defaults: {
        keyAlgorithm: "RSA_4096",
        signatureAlgorithm: "RSA-SHA512",
        keyUsages: ["digital_signature"],
        extendedKeyUsages: ["server_auth"]
      },
      keyUsages: null,
      extendedKeyUsages: null
    });

    await service.issueCertificate("request-id");

    expect(queueCertificateIssuance).toHaveBeenCalledWith(
      expect.objectContaining({
        keyAlgorithm: "RSA_4096",
        signatureAlgorithm: "RSA-SHA512",
        keyUsages: ["digitalSignature"],
        extendedKeyUsages: ["serverAuth"]
      })
    );
  });
});
