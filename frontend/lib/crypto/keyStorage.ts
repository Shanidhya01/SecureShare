/**
 * Private-key-at-rest handling: encrypting/decrypting a user's private keys (RSA encryption key,
 * ECDSA signing key) with a password-derived key, and persisting the resulting (still-encrypted)
 * blobs in IndexedDB.
 *
 * The plaintext private key exists only in memory for as long as it's in use - it is NEVER
 * written to localStorage and NEVER sent over the network. Only the AES-GCM-encrypted blob
 * (useless without the user's login password) is persisted, in IndexedDB, keyed by email.
 */
import { bufToBase64, base64ToBuf } from "./base64";
import { deriveKeyPBKDF2, DEFAULT_PBKDF2_ITERATIONS } from "./pbkdf2";

const DB_NAME = "secureshare-keystore";
const DB_VERSION = 1;
const STORE_NAME = "privateKeys";

export type StoredKeyRecord = {
  email: string;
  // RSA-OAEP encryption keypair (Phase 1)
  wrappedPrivateKey: string;
  salt: string;
  iv: string;
  iterations: number;
  publicKeyBase64: string;
  // ECDSA P-256 signing keypair (Phase 2) - optional so Phase 1 records remain valid;
  // CryptoKeyContext lazily backfills these fields on next unlock for pre-Phase-2 accounts.
  wrappedSigningPrivateKey?: string;
  signingSalt?: string;
  signingIv?: string;
  signingIterations?: number;
  signingPublicKeyBase64?: string;
  createdAt: number;
};

// ---------------------------------------------------------------------------
// Encrypt/decrypt private key bytes (PBKDF2-SHA256 -> AES-GCM). Algorithm-agnostic - works
// for any CryptoKey exportable as PKCS8 (RSA-OAEP or ECDSA), since the wrap/unwrap step only
// ever operates on the exported byte string, not the key's algorithm.
// ---------------------------------------------------------------------------

/** Encrypts a private key (exported as PKCS8) with an AES-GCM key derived from the user's
 *  login password, so it can be safely persisted in IndexedDB. Works for any private key type
 *  (RSA-OAEP, ECDSA, ...) since PKCS8 export/import is algorithm-agnostic at this layer. */
export async function encryptPrivateKey(
  privateKey: CryptoKey,
  loginPassword: string,
  iterations: number = DEFAULT_PBKDF2_ITERATIONS
): Promise<{ wrappedPrivateKey: string; salt: string; iv: string; iterations: number }> {
  const pkcs8 = await crypto.subtle.exportKey("pkcs8", privateKey);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const derivedKey = await deriveKeyPBKDF2(loginPassword, salt, iterations, ["encrypt", "decrypt"]);
  const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, derivedKey, pkcs8);
  return {
    wrappedPrivateKey: bufToBase64(encrypted),
    salt: bufToBase64(salt),
    iv: bufToBase64(iv),
    iterations,
  };
}

/** Reverses encryptPrivateKey, returning the raw decrypted PKCS8 bytes (not yet imported into
 *  a CryptoKey) so callers can import it with whichever algorithm the key actually is - see
 *  decryptPrivateKey (RSA-OAEP) below and ecdsa.ts's decryptSigningPrivateKey (ECDSA). */
export async function decryptPrivateKeyBytes(
  wrappedPrivateKeyBase64: string,
  loginPassword: string,
  saltBase64: string,
  ivBase64: string,
  iterations: number
): Promise<ArrayBuffer> {
  const salt = base64ToBuf(saltBase64);
  const iv = base64ToBuf(ivBase64);
  const derivedKey = await deriveKeyPBKDF2(loginPassword, salt, iterations, ["encrypt", "decrypt"]);
  return crypto.subtle.decrypt({ name: "AES-GCM", iv }, derivedKey, base64ToBuf(wrappedPrivateKeyBase64));
}

/** Reverses encryptPrivateKey for the RSA-OAEP encryption keypair specifically, given the login
 *  password re-entered by the user ("unlock"). */
export async function decryptPrivateKey(
  wrappedPrivateKeyBase64: string,
  loginPassword: string,
  saltBase64: string,
  ivBase64: string,
  iterations: number
): Promise<CryptoKey> {
  const pkcs8 = await decryptPrivateKeyBytes(wrappedPrivateKeyBase64, loginPassword, saltBase64, ivBase64, iterations);
  return crypto.subtle.importKey("pkcs8", pkcs8, { name: "RSA-OAEP", hash: "SHA-256" }, false, ["unwrapKey"]);
}

// ---------------------------------------------------------------------------
// IndexedDB persistence (never localStorage)
// ---------------------------------------------------------------------------

function openKeyStoreDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME, { keyPath: "email" });
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

/** Persists an already-encrypted private key record for a user in IndexedDB. */
export async function savePrivateKeyIndexedDB(email: string, record: Omit<StoredKeyRecord, "email">): Promise<void> {
  const db = await openKeyStoreDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, "readwrite");
    tx.objectStore(STORE_NAME).put({ email, ...record });
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

/** Loads a user's encrypted private key record from IndexedDB, or null if none exists on this device. */
export async function loadPrivateKeyIndexedDB(email: string): Promise<StoredKeyRecord | null> {
  const db = await openKeyStoreDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, "readonly");
    const req = tx.objectStore(STORE_NAME).get(email);
    req.onsuccess = () => resolve(req.result || null);
    req.onerror = () => reject(req.error);
  });
}

export async function hasLocalKeypair(email: string): Promise<boolean> {
  const record = await loadPrivateKeyIndexedDB(email);
  return !!record;
}

export async function clearPrivateKeyIndexedDB(email: string): Promise<void> {
  const db = await openKeyStoreDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, "readwrite");
    tx.objectStore(STORE_NAME).delete(email);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}
