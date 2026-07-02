/**
 * Low-level AES-256-GCM primitives. File-level encrypt/decrypt orchestration lives in
 * fileEncryption.ts; this module only covers key generation and raw key import/export.
 */

/** Generates a fresh, unique AES-256-GCM key for a single file. Extractable so it can later
 *  be wrapped (RSA or password) or exported raw for fragment-based sharing. */
export async function generateAESKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
}

/** Exports an AES-GCM key to raw bytes - used only for the no-password fragment-key sharing
 *  case, where the raw key must be embedded directly in the URL fragment. */
export async function exportAESKeyRaw(key: CryptoKey): Promise<ArrayBuffer> {
  return crypto.subtle.exportKey("raw", key);
}

/** Re-imports raw AES key bytes (e.g. parsed out of a URL fragment) into a usable CryptoKey. */
export async function importAESKeyRaw(raw: ArrayBuffer): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["decrypt"]);
}
