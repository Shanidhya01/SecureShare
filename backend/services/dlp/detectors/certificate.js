export const id = "certificate";
export const label = "X.509 Certificate";
export const category = "Cryptographic Material";
// Certificates are usually public material (the public half of a keypair), so this is flagged
// at a lower severity than private keys - mainly informational, to catch accidental bundling of
// internal CA/cert chains rather than an outright secret leak.
export const severity = "Low";

const PATTERN = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;

export function detect(text) {
  const matches = text.match(PATTERN);
  if (matches) return matches;
  const header = text.match(/-----BEGIN CERTIFICATE-----/g);
  return header || [];
}
