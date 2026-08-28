import { BadRequestError } from "@app/lib/errors";
import { isValidIp } from "@app/lib/ip";
import { isPrivateIp } from "@app/lib/ip/ipRange";
import { isFQDN } from "@app/lib/validator/validate-url";
import {
  DIGICERT_CS_PRODUCT_NAME_IDS,
  isDigiCertX9Product
} from "@app/services/app-connection/digicert/digicert-connection-fns";
import { CertKeyAlgorithm } from "@app/services/certificate/certificate-types";
import {
  CertExtendedKeyUsageType,
  CertKeyUsageType,
  mapLegacyExtendedKeyUsageToStandard,
  mapLegacyKeyUsageToStandard
} from "@app/services/certificate-common/certificate-constants";

import { DigiCertCaPurpose, DigiCertDcvScope } from "./digicert-certificate-authority-schemas";

export const assertDigiCertPurposeMatchesProduct = (
  purpose: DigiCertCaPurpose | undefined,
  productNameId: string,
  certificateDcvScope?: DigiCertDcvScope
): DigiCertCaPurpose => {
  const isX9Product = isDigiCertX9Product(productNameId);
  const effectivePurpose = purpose ?? (isX9Product ? DigiCertCaPurpose.X9Pki : DigiCertCaPurpose.Ssl);
  const isCsProduct = DIGICERT_CS_PRODUCT_NAME_IDS.has(productNameId);
  if (effectivePurpose === DigiCertCaPurpose.CodeSigning && !isCsProduct) {
    throw new BadRequestError({
      message: `Product '${productNameId}' is not a code-signing product. Pick one of: ${[...DIGICERT_CS_PRODUCT_NAME_IDS].join(", ")}`
    });
  }
  if (effectivePurpose === DigiCertCaPurpose.Ssl && isCsProduct) {
    throw new BadRequestError({
      message: `Product '${productNameId}' is a code-signing product but this CA is configured for SSL`
    });
  }
  if (effectivePurpose === DigiCertCaPurpose.X9Pki && !isX9Product) {
    throw new BadRequestError({
      message: `Product '${productNameId}' is not the DigiCert X9 PKI for TLS product. Use 'x9_pki' instead`
    });
  }
  if (effectivePurpose !== DigiCertCaPurpose.X9Pki && isX9Product) {
    throw new BadRequestError({ message: "Product 'x9_pki' requires the X9 PKI for TLS purpose" });
  }
  if (certificateDcvScope && effectivePurpose !== DigiCertCaPurpose.X9Pki) {
    throw new BadRequestError({
      message: "Certificate DCV scope is only supported for X9 PKI for TLS certificate authorities"
    });
  }
  return effectivePurpose;
};

const DIGICERT_X9_ALLOWED_KEY_ALGORITHMS = new Set<string>([
  CertKeyAlgorithm.RSA_2048,
  CertKeyAlgorithm.RSA_3072,
  CertKeyAlgorithm.RSA_4096,
  CertKeyAlgorithm.ECDSA_P256,
  CertKeyAlgorithm.ECDSA_P384
]);

export const assertDigiCertX9KeyAlgorithm = (keyAlgorithm?: string | null) => {
  if (!keyAlgorithm || !DIGICERT_X9_ALLOWED_KEY_ALGORITHMS.has(keyAlgorithm)) {
    throw new BadRequestError({
      message: "DigiCert X9 PKI for TLS supports RSA_2048, RSA_3072, RSA_4096, EC_prime256v1, and EC_secp384r1 keys"
    });
  }
};

type TDigiCertX9OrderOptions = {
  dcvMethod: "dns-txt-token" | "http-token";
  keyUsages?: Array<"digital_signature" | "key_agreement_encipherment">;
  extendedKeyUsages?: Array<"server_authentication" | "client_authentication">;
};

type TDigiCertX9SignatureHash = "sha256" | "sha384" | "sha512";

export const resolveDigiCertX9SignatureHash = (
  keyAlgorithm?: string | null,
  signatureAlgorithm?: string | null
): TDigiCertX9SignatureHash => {
  assertDigiCertX9KeyAlgorithm(keyAlgorithm);

  if (keyAlgorithm === CertKeyAlgorithm.ECDSA_P256) return "sha256";
  if (keyAlgorithm === CertKeyAlgorithm.ECDSA_P384) return "sha384";

  const normalizedSignature = signatureAlgorithm?.toLowerCase() ?? "";
  if (normalizedSignature.includes("sha512")) return "sha512";
  return normalizedSignature.includes("sha384") ? "sha384" : "sha256";
};

const mapDigiCertX9KeyUsage = (usage: string): "digital_signature" | "key_agreement_encipherment" => {
  let normalizedUsage: CertKeyUsageType;
  try {
    normalizedUsage = mapLegacyKeyUsageToStandard(usage);
  } catch {
    throw new BadRequestError({ message: `DigiCert X9 PKI for TLS does not support key usage '${usage}'` });
  }
  switch (normalizedUsage) {
    case CertKeyUsageType.DIGITAL_SIGNATURE:
      return "digital_signature";
    case CertKeyUsageType.KEY_ENCIPHERMENT:
    case CertKeyUsageType.KEY_AGREEMENT:
      return "key_agreement_encipherment";
    default:
      throw new BadRequestError({ message: `DigiCert X9 PKI for TLS does not support key usage '${usage}'` });
  }
};

const mapDigiCertX9ExtendedKeyUsage = (usage: string): "server_authentication" | "client_authentication" => {
  let normalizedUsage: CertExtendedKeyUsageType;
  try {
    normalizedUsage = mapLegacyExtendedKeyUsageToStandard(usage);
  } catch {
    throw new BadRequestError({ message: `DigiCert X9 PKI for TLS does not support extended key usage '${usage}'` });
  }
  switch (normalizedUsage) {
    case CertExtendedKeyUsageType.SERVER_AUTH:
      return "server_authentication";
    case CertExtendedKeyUsageType.CLIENT_AUTH:
      return "client_authentication";
    default:
      throw new BadRequestError({ message: `DigiCert X9 PKI for TLS does not support extended key usage '${usage}'` });
  }
};

export const resolveDigiCertX9OrderOptions = ({
  commonName,
  altNames,
  keyUsages,
  extendedKeyUsages
}: {
  commonName: string;
  altNames: string[];
  keyUsages?: string[];
  extendedKeyUsages?: string[];
}): TDigiCertX9OrderOptions => {
  const names = [commonName, ...altNames].map((name) => name.trim());
  const wildcard = names.find((name) => name.startsWith("*."));
  if (wildcard) {
    throw new BadRequestError({ message: `DigiCert X9 PKI for TLS does not support wildcard domain '${wildcard}'` });
  }
  const invalidName = names.find((name) => !isFQDN(name) && !isValidIp(name));
  if (invalidName) {
    throw new BadRequestError({
      message: `DigiCert X9 PKI for TLS supports only fully qualified domain names and IP addresses. '${invalidName}' is not supported`
    });
  }
  const nonPublicIp = names.find((name) => isValidIp(name) && isPrivateIp(name));
  if (nonPublicIp) {
    throw new BadRequestError({
      message: `DigiCert X9 PKI for TLS supports only public IP addresses. '${nonPublicIp}' is not publicly routable`
    });
  }

  const mappedKeyUsages = [...new Set((keyUsages ?? []).map(mapDigiCertX9KeyUsage))];
  const mappedExtendedKeyUsages = [...new Set((extendedKeyUsages ?? []).map(mapDigiCertX9ExtendedKeyUsage))];

  return {
    dcvMethod: names.some(isValidIp) ? "http-token" : "dns-txt-token",
    ...(mappedKeyUsages.length > 0 ? { keyUsages: mappedKeyUsages } : {}),
    ...(mappedExtendedKeyUsages.length > 0 ? { extendedKeyUsages: mappedExtendedKeyUsages } : {})
  };
};

export const resolveDigiCertX9IssuanceOptions = ({
  keyAlgorithm,
  signatureAlgorithm,
  ...orderOptions
}: {
  keyAlgorithm?: string | null;
  signatureAlgorithm?: string | null;
  commonName: string;
  altNames: string[];
  keyUsages?: string[];
  extendedKeyUsages?: string[];
}) => ({
  ...resolveDigiCertX9OrderOptions(orderOptions),
  signatureHash: resolveDigiCertX9SignatureHash(keyAlgorithm, signatureAlgorithm)
});
