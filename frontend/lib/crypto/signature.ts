/**
 * Phase 2: digital signature + integrity verification over the encrypted file, combining
 * hash.ts (SHA-256) and ecdsa.ts (ECDSA P-256). This is the module upload/download pages
 * should call directly rather than composing hash+sign/verify themselves.
 *
 * Signature covers the CIPHERTEXT (the encrypted file bytes), not the plaintext - it proves
 * "this exact encrypted blob was produced and signed by the holder of this signing key," which
 * is what a downloader needs to check *before* spending the effort of decrypting: if the
 * ciphertext were tampered with in transit or at rest (e.g. a compromised Cloudinary object),
 * the signature check fails immediately, without ever touching the AES key.
 *
 * Implementation note: the Web Crypto API's ECDSA sign/verify operations always hash their
 * input internally per the `hash` algorithm parameter - there is no "sign this already-hashed
 * digest verbatim" mode. Signing the ciphertext with `hash: "SHA-256"` is therefore the
 * standards-correct way to "sign the SHA-256 hash of the file": the signature is mathematically
 * over SHA-256(ciphertext), identical to what a manual hash-then-sign two-step would produce.
 * fileHash is computed as a separate, explicit SHA-256 digest purely for the metadata fields
 * requested (display/audit) - it is never itself trusted as the basis for verification; only
 * cryptographic signature verification decides pass/fail.
 */
import { sha256Base64 } from "./hash";
import { bufToBase64, base64ToBuf } from "./base64";

export const HASH_ALGORITHM = "SHA-256";
export const SIGNATURE_ALGORITHM = "ECDSA-P256-SHA256";

export type FileSignature = {
  signature: string;         // base64 ECDSA signature over the ciphertext
  fileHash: string;          // base64 SHA-256 digest of the ciphertext (informational)
  hashAlgorithm: string;     // "SHA-256"
  signatureAlgorithm: string; // "ECDSA-P256-SHA256"
  signedAt: string;          // ISO 8601 timestamp
};

/** Computes the SHA-256 hash of an encrypted file and signs it with the uploader's ECDSA
 *  P-256 private signing key. Call this after AES-GCM encryption, before uploading. */
export async function signEncryptedFile(
  ciphertext: ArrayBuffer,
  signingPrivateKey: CryptoKey
): Promise<FileSignature> {
  const [fileHash, signatureBytes] = await Promise.all([
    sha256Base64(ciphertext),
    crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, signingPrivateKey, ciphertext),
  ]);

  return {
    signature: bufToBase64(signatureBytes),
    fileHash,
    hashAlgorithm: HASH_ALGORITHM,
    signatureAlgorithm: SIGNATURE_ALGORITHM,
    signedAt: new Date().toISOString(),
  };
}

/** Verifies a downloaded encrypted file's signature against the uploader's ECDSA public signing
 *  key, BEFORE decryption. Returns false (never throws for a bad signature) so callers can
 *  branch on the result directly - a tampered/forged file must never proceed to decryption. */
export async function verifyEncryptedFileSignature(
  ciphertext: ArrayBuffer,
  signatureBase64: string,
  signingPublicKey: CryptoKey
): Promise<boolean> {
  try {
    return await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      signingPublicKey,
      base64ToBuf(signatureBase64),
      ciphertext
    );
  } catch {
    return false;
  }
}
