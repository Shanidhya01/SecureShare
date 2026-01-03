import crypto from "crypto";

export function encryptBuffer(buffer) {
  const aesKey = crypto.randomBytes(32);
  const iv = crypto.randomBytes(16);

  const cipher = crypto.createCipheriv("aes-256-cbc", aesKey, iv);
  const encrypted = Buffer.concat([cipher.update(buffer), cipher.final()]);

  return { encrypted, aesKey, iv };
}
