/**
 * SHA-256 hashing, used by signature.ts to compute the integrity hash of an encrypted file
 * (Phase 2). Exposed standalone so the hash can also be displayed/logged for diagnostics
 * without needing a signing key.
 */
import { bufToBase64 } from "./base64";

/** Computes the raw SHA-256 digest of the given bytes. */
export async function sha256(data: BufferSource): Promise<ArrayBuffer> {
  return crypto.subtle.digest("SHA-256", data);
}

/** Computes the SHA-256 digest and returns it base64-encoded, matching this app's convention
 *  for encoding binary values (IVs, keys, signatures, ...) in JSON/FormData. */
export async function sha256Base64(data: BufferSource): Promise<string> {
  const digest = await sha256(data);
  return bufToBase64(digest);
}
