// LEGACY (encryptionVersion 1): server-side AES-256-CBC decryption, still required by downloadFileV1
// for files uploaded before the client-side E2E (v2) migration. Filename typo intentionally preserved.
import crypto from "crypto";

export function decryptBuffer(encrypted, key, iv) {
  const decipher = crypto.createDecipheriv("aes-256-cbc", key, iv);
  return Buffer.concat([decipher.update(encrypted), decipher.final()]);
}
