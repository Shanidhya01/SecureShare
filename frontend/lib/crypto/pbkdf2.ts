/**
 * PBKDF2-SHA256 password-derived key wrapping - used for password-protected share links, where
 * the AES file key is wrapped with a key derived from the share password rather than RSA. The
 * server stores the wrapped key + salt but never receives (or validates) the password itself;
 * a wrong password simply causes AES-GCM authentication to fail during unwrap.
 */
import { bufToBase64, base64ToBuf } from "./base64";

export const DEFAULT_PBKDF2_ITERATIONS = 210000;

/** Derives an AES-256-GCM "wrapping key" from a plaintext password + salt via PBKDF2-SHA256. */
export async function deriveKeyPBKDF2(
  password: string,
  salt: BufferSource,
  iterations: number = DEFAULT_PBKDF2_ITERATIONS,
  usages: KeyUsage[] = ["wrapKey", "unwrapKey"]
): Promise<CryptoKey> {
  const baseKey = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    usages
  );
}

/** Wraps the file's AES key using a key derived from a share password. Generates its own
 *  random salt and IV for the wrap operation (distinct from the file's own content IV). */
export async function wrapAESKeyWithPassword(
  aesKey: CryptoKey,
  password: string,
  iterations: number = DEFAULT_PBKDF2_ITERATIONS
): Promise<{ wrapped: string; salt: string; iv: string; iterations: number }> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const derivedKey = await deriveKeyPBKDF2(password, salt, iterations, ["wrapKey"]);
  const wrapped = await crypto.subtle.wrapKey("raw", aesKey, derivedKey, { name: "AES-GCM", iv });
  return { wrapped: bufToBase64(wrapped), salt: bufToBase64(salt), iv: bufToBase64(iv), iterations };
}

/** Reverses wrapAESKeyWithPassword. Throws (GCM tag mismatch) if the password is wrong. */
export async function unwrapAESKeyWithPassword(
  wrappedBase64: string,
  password: string,
  saltBase64: string,
  ivBase64: string,
  iterations: number
): Promise<CryptoKey> {
  const salt = base64ToBuf(saltBase64);
  const iv = base64ToBuf(ivBase64);
  const derivedKey = await deriveKeyPBKDF2(password, salt, iterations, ["unwrapKey"]);
  return crypto.subtle.unwrapKey(
    "raw",
    base64ToBuf(wrappedBase64),
    derivedKey,
    { name: "AES-GCM", iv },
    { name: "AES-GCM", length: 256 },
    true,
    ["decrypt"]
  );
}
