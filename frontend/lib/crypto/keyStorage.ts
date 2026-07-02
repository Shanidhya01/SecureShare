/**
 * Private-key-at-rest handling: encrypting/decrypting a user's RSA private key with a
 * password-derived key, and persisting the resulting (still-encrypted) blob in IndexedDB.
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
  wrappedPrivateKey: string;
  salt: string;
  iv: string;
  iterations: number;
  publicKeyBase64: string;
  createdAt: number;
};

// ---------------------------------------------------------------------------
// Encrypt/decrypt the private key bytes (PBKDF2-SHA256 -> AES-GCM)
// ---------------------------------------------------------------------------

/** Encrypts a user's RSA private key (exported as PKCS8) with an AES-GCM key derived from
 *  their login password, so it can be safely persisted in IndexedDB. */
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

/** Reverses encryptPrivateKey given the login password re-entered by the user ("unlock"). */
export async function decryptPrivateKey(
  wrappedPrivateKeyBase64: string,
  loginPassword: string,
  saltBase64: string,
  ivBase64: string,
  iterations: number
): Promise<CryptoKey> {
  const salt = base64ToBuf(saltBase64);
  const iv = base64ToBuf(ivBase64);
  const derivedKey = await deriveKeyPBKDF2(loginPassword, salt, iterations, ["encrypt", "decrypt"]);
  const pkcs8 = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, derivedKey, base64ToBuf(wrappedPrivateKeyBase64));
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
