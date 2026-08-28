import { describe, expect, it } from "vitest";

import { CertKeyAlgorithm } from "@app/services/certificate/certificate-types";

import { DigiCertCaPurpose, DigiCertDcvScope } from "./digicert-certificate-authority-schemas";
import {
  assertDigiCertPurposeMatchesProduct,
  assertDigiCertX9KeyAlgorithm,
  resolveDigiCertX9OrderOptions,
  resolveDigiCertX9SignatureHash
} from "./digicert-certificate-authority-validators";

describe("assertDigiCertPurposeMatchesProduct", () => {
  it("infers the X9 purpose from its product and accepts its DCV scope", () => {
    expect(assertDigiCertPurposeMatchesProduct(undefined, "x9_pki", DigiCertDcvScope.BaseDomain)).toBe(
      DigiCertCaPurpose.X9Pki
    );
  });

  it("rejects a DCV scope for non-X9 products", () => {
    expect(() => assertDigiCertPurposeMatchesProduct(DigiCertCaPurpose.Ssl, "ssl_plus", DigiCertDcvScope.Fqdn)).toThrow(
      "Certificate DCV scope is only supported for X9 PKI for TLS certificate authorities"
    );
  });

  it("rejects an X9 purpose with another product", () => {
    expect(() => assertDigiCertPurposeMatchesProduct(DigiCertCaPurpose.X9Pki, "ssl_plus")).toThrow(
      "Product 'ssl_plus' is not the DigiCert X9 PKI for TLS product"
    );
  });
});

describe("resolveDigiCertX9OrderOptions", () => {
  it("maps supported key usages and uses HTTP validation for IP addresses", () => {
    expect(
      resolveDigiCertX9OrderOptions({
        commonName: "api.example.com",
        altNames: ["1.1.1.1"],
        keyUsages: ["digitalSignature", "keyAgreement"],
        extendedKeyUsages: ["serverAuth", "client_auth"]
      })
    ).toEqual({
      dcvMethod: "http-token",
      keyUsages: ["digital_signature", "key_agreement_encipherment"],
      extendedKeyUsages: ["server_authentication", "client_authentication"]
    });
  });

  it("uses DNS TXT validation for FQDN-only requests", () => {
    expect(resolveDigiCertX9OrderOptions({ commonName: "api.example.com", altNames: ["www.example.com"] })).toEqual({
      dcvMethod: "dns-txt-token"
    });
  });

  it("rejects unsupported wildcard names and key usages", () => {
    expect(() => resolveDigiCertX9OrderOptions({ commonName: "*.example.com", altNames: [] })).toThrow(
      "does not support wildcard domain '*.example.com'"
    );
    expect(() =>
      resolveDigiCertX9OrderOptions({ commonName: "api.example.com", altNames: [], keyUsages: ["keyCertSign"] })
    ).toThrow("does not support key usage 'keyCertSign'");
  });

  it("rejects non-public IPs and unsupported key algorithms", () => {
    expect(() => resolveDigiCertX9OrderOptions({ commonName: "10.0.0.1", altNames: [] })).toThrow(
      "supports only public IP addresses"
    );
    expect(() => assertDigiCertX9KeyAlgorithm(CertKeyAlgorithm.ECDSA_P521)).toThrow("supports RSA_2048");
  });

  it("uses curve-matched hashes for ECC and supports all X9 RSA hashes", () => {
    expect(resolveDigiCertX9SignatureHash(CertKeyAlgorithm.ECDSA_P256, "ECDSA-SHA384")).toBe("sha256");
    expect(resolveDigiCertX9SignatureHash(CertKeyAlgorithm.ECDSA_P384, "ECDSA-SHA256")).toBe("sha384");
    expect(resolveDigiCertX9SignatureHash(CertKeyAlgorithm.RSA_4096, "RSA-SHA384")).toBe("sha384");
    expect(resolveDigiCertX9SignatureHash(CertKeyAlgorithm.RSA_2048, "RSA-SHA512")).toBe("sha512");
  });
});
