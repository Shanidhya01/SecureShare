import crypto from "crypto";

/** Computes SHA-256, SHA-1, and MD5 hashes of a buffer. MD5/SHA-1 are included only for
 *  interoperability with legacy threat-intel tooling and hash-based lookups that still key on
 *  them (e.g. some malware databases) - SHA-256 is the one used for VirusTotal lookups and as
 *  the primary identity hash, since MD5/SHA-1 are cryptographically broken for collision
 *  resistance and must never be relied on as an integrity guarantee. */
export function computeFileHashes(buffer) {
  return {
    sha256: crypto.createHash("sha256").update(buffer).digest("hex"),
    sha1: crypto.createHash("sha1").update(buffer).digest("hex"),
    md5: crypto.createHash("md5").update(buffer).digest("hex")
  };
}
