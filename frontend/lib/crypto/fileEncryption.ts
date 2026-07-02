/**
 * File-level AES-256-GCM encryption/decryption. This is the only place plaintext file bytes
 * are ever touched - callers pass a File in, get ciphertext out, and vice versa. The server
 * never sees either side of this boundary.
 */

/** Encrypts a File's contents with AES-256-GCM using a random 96-bit IV. The returned
 *  ciphertext has the GCM authentication tag appended automatically by SubtleCrypto - if the
 *  ciphertext is tampered with, decryptFile() will throw (integrity verification failure). */
export async function encryptFile(
  file: File,
  key: CryptoKey
): Promise<{ ciphertext: ArrayBuffer; iv: Uint8Array }> {
  const iv = crypto.getRandomValues(new Uint8Array(12)); // 96-bit IV, per AES-GCM best practice
  const data = await file.arrayBuffer();
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, data);
  return { ciphertext, iv };
}

/** Decrypts ciphertext (with the GCM tag appended) back to plaintext bytes. Throws if the
 *  key/IV is wrong or the ciphertext was tampered with - this doubles as the integrity check
 *  and the "wrong key/password" signal, since AES-GCM authentication fails in both cases. */
export async function decryptFile(
  ciphertext: ArrayBuffer,
  key: CryptoKey,
  iv: BufferSource
): Promise<ArrayBuffer> {
  return crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext);
}
