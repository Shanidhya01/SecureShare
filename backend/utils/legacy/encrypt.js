// LEGACY (encryptionVersion 1): server-side AES-256-CBC encryption using a random per-file key/IV,
// wrapped with the global RSA keypair (backend/keys/*.pem). Only used by uploadFileV1 for backward
// compatibility with files uploaded before the client-side E2E (v2) migration. Do not use for new uploads.
import crypto from "crypto";

export const encryptBuffer = (buffer) => {
  const aesKey = crypto.randomBytes(32);
  const iv = crypto.randomBytes(16);

  const cipher = crypto.createCipheriv("aes-256-cbc", aesKey, iv);
  const encrypted = Buffer.concat([cipher.update(buffer), cipher.final()]);

  return { encrypted, aesKey, iv };
};
