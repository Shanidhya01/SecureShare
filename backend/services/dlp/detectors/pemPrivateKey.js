export const id = "pem_private_key";
export const label = "PEM Private Key";
export const category = "Cryptographic Material";
export const severity = "Critical";

const PATTERN = /-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED |)PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |DSA |ENCRYPTED |)PRIVATE KEY-----/g;

export function detect(text) {
  const matches = text.match(PATTERN);
  if (matches) return matches;
  // Fall back to the header alone in case the file is truncated / the footer is missing.
  const header = text.match(/-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED |)PRIVATE KEY-----/g);
  return header || [];
}
