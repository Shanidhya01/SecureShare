/**
 * RSA-OAEP-SHA256 primitives for the "owner access" key-wrapping path: every user has their
 * own RSA keypair, generated client-side. The public key is uploaded to the server; the
 * private key never leaves the browser (see keyStorage.ts).
 */
import { bufToBase64, base64ToBuf } from "./base64";

/** Generates a per-account RSA-OAEP-SHA256 keypair. 3072-bit by default for extra long-term
 *  margin above the 2048-bit minimum - cheap in practice since we only ever wrap a single
 *  32-byte AES key with it. */
export async function generateRSAKeyPair(modulusLength: 2048 | 3072 = 3072): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["wrapKey", "unwrapKey"]
  ) as Promise<CryptoKeyPair>;
}

/** Exports a public key as base64-encoded SPKI, for upload to the server. */
export async function exportPublicKey(key: CryptoKey): Promise<string> {
  const spki = await crypto.subtle.exportKey("spki", key);
  return bufToBase64(spki);
}

/** Imports a base64 SPKI public key (fetched from the server) back into a usable CryptoKey. */
export async function importPublicKey(base64Spki: string): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "spki",
    base64ToBuf(base64Spki),
    { name: "RSA-OAEP", hash: "SHA-256" },
    true,
    ["wrapKey"]
  );
}

/** Wraps (encrypts) an AES-GCM key with an RSA-OAEP public key. Returns base64 wrapped bytes. */
export async function wrapAESKey(aesKey: CryptoKey, rsaPublicKey: CryptoKey): Promise<string> {
  const wrapped = await crypto.subtle.wrapKey("raw", aesKey, rsaPublicKey, { name: "RSA-OAEP" });
  return bufToBase64(wrapped);
}

/** Unwraps a base64 RSA-OAEP-wrapped AES key using the owner's private key. */
export async function unwrapAESKey(wrappedBase64: string, rsaPrivateKey: CryptoKey): Promise<CryptoKey> {
  return crypto.subtle.unwrapKey(
    "raw",
    base64ToBuf(wrappedBase64),
    rsaPrivateKey,
    { name: "RSA-OAEP" },
    { name: "AES-GCM", length: 256 },
    true,
    ["decrypt"]
  );
}
