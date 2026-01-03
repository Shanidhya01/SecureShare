import crypto from "crypto";

export function decryptBuffer(encrypted, key, iv) {
  const decipher = crypto.createDecipheriv("aes-256-cbc", key, iv);
  return Buffer.concat([decipher.update(encrypted), decipher.final()]);
}
