/**
 * ECDSA P-256 primitives for Phase 2 digital signatures. This is a keypair entirely separate
 * from the RSA-OAEP encryption keypair in rsa.ts - encryption and signing keys should never be
 * shared, since they serve different security properties (confidentiality vs. authenticity).
 *
 * Every user generates their own ECDSA P-256 signing keypair client-side. The public key is
 * uploaded to the server (User.signingPublicKey) so anyone downloading their files can verify
 * authenticity; the private signing key is encrypted and stored only in IndexedDB, exactly like
 * the RSA private key (see keyStorage.ts).
 */
import { bufToBase64, base64ToBuf } from "./base64";
import { decryptPrivateKeyBytes } from "./keyStorage";

/** Generates a per-account ECDSA P-256 signing keypair. */
export async function generateSigningKeyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"]
  ) as Promise<CryptoKeyPair>;
}

/** Exports a signing public key as base64-encoded SPKI, for upload to the server. */
export async function exportSigningPublicKey(key: CryptoKey): Promise<string> {
  const spki = await crypto.subtle.exportKey("spki", key);
  return bufToBase64(spki);
}

/** Imports a base64 SPKI signing public key (fetched from the server, embedded in file
 *  metadata) into a usable CryptoKey for signature verification. */
export async function importSigningPublicKey(base64Spki: string): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "spki",
    base64ToBuf(base64Spki),
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["verify"]
  );
}

/** Imports raw PKCS8 bytes (already decrypted) as an ECDSA signing private key. */
export async function importSigningPrivateKeyFromPKCS8(pkcs8: ArrayBuffer): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "pkcs8",
    pkcs8,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"]
  );
}

/** Reverses keyStorage.ts's encryptPrivateKey for the ECDSA signing keypair specifically -
 *  decrypts the wrapped PKCS8 bytes with the login password, then imports as ECDSA P-256. */
export async function decryptSigningPrivateKey(
  wrappedPrivateKeyBase64: string,
  loginPassword: string,
  saltBase64: string,
  ivBase64: string,
  iterations: number
): Promise<CryptoKey> {
  const pkcs8 = await decryptPrivateKeyBytes(wrappedPrivateKeyBase64, loginPassword, saltBase64, ivBase64, iterations);
  return importSigningPrivateKeyFromPKCS8(pkcs8);
}
