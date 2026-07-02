/**
 * SecureShare zero-knowledge crypto module - public entry point.
 *
 * Everything under frontend/lib/crypto/ runs in the browser via the native Web Crypto API
 * (window.crypto.subtle). The server never sees plaintext file bytes, raw AES keys, or RSA
 * private key material - it only ever receives ciphertext and keys wrapped with RSA-OAEP or
 * a password-derived key.
 *
 * Key model:
 * - Every file gets a fresh AES-256-GCM key + random 96-bit IV (generateAESKey/encryptFile).
 * - The AES key is wrapped for the uploader's own RSA-OAEP public key (wrapAESKey), so the
 *   owner can always re-access the file from their dashboard.
 * - For sharing, either the raw AES key travels in the URL fragment (exportAESKeyRaw -
 *   fragments are never sent to the server), or, if a share password is set, the AES key is
 *   wrapped with a PBKDF2-derived key from that password (wrapAESKeyWithPassword).
 * - Each user's own RSA private key is wrapped with a PBKDF2-derived key from their login
 *   password and stored only in IndexedDB (keyStorage.ts) - never uploaded anywhere.
 *
 * Other modules should generally import from here rather than reaching into the individual
 * aes.ts/rsa.ts/pbkdf2.ts/fileEncryption.ts/keyStorage.ts files directly.
 */

export * from "./base64";
export * from "./aes";
export * from "./fileEncryption";
export * from "./rsa";
export * from "./pbkdf2";
export * from "./keyStorage";
