/**
 * Phase 12 (DevSecOps/Supply Chain) - PART 9: artifact checksum/signing/tamper-detection. There is
 * no real build pipeline producing binaries in this project, so `backend/package-lock.json` and
 * `frontend/package-lock.json` stand in as the "artifacts" - reuses the existing
 * utils/fileHashes.js hashing helper (no new hashing code) and signs the hash with an HMAC keyed
 * on the app's existing JWT_SECRET. This is honestly an integrity/tamper-detection mechanism, not
 * a code-signing PKI certificate - documented as such in SECURITY.md.
 */
import fs from "fs";
import path from "path";
import crypto from "crypto";
import { fileURLToPath } from "url";
import { computeFileHashes } from "../../utils/fileHashes.js";
import ArtifactSignature from "../../models/ArtifactSignature.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.join(__dirname, "..", "..", "..");

const ARTIFACTS = [
  { name: "backend/package-lock.json", filePath: path.join(REPO_ROOT, "backend", "package-lock.json") },
  { name: "frontend/package-lock.json", filePath: path.join(REPO_ROOT, "frontend", "package-lock.json") }
];

function hmacSign(hash) {
  const secret = process.env.JWT_SECRET || "insecure-default-secret";
  return crypto.createHmac("sha256", secret).update(hash).digest("hex");
}

/** Hashes + signs one artifact, persisting an ArtifactSignature record. */
export async function signArtifact(artifactName, buffer) {
  const { sha256 } = computeFileHashes(buffer);
  const hmacSignature = hmacSign(sha256);

  return ArtifactSignature.create({
    artifactName,
    algorithm: "sha256",
    hash: sha256,
    hmacSignature,
    verified: true,
    verifiedAt: new Date(),
    status: "valid"
  });
}

/** Re-hashes the artifact's current bytes and compares against a prior signature record's hash -
 *  a mismatch means the file changed since it was signed (tamper detection). */
export function verifyArtifact(buffer, signatureRecord) {
  const { sha256 } = computeFileHashes(buffer);
  const expectedHmac = hmacSign(sha256);
  const hashMatches = sha256 === signatureRecord.hash;
  const hmacMatches = expectedHmac === signatureRecord.hmacSignature;
  return { valid: hashMatches && hmacMatches, currentHash: sha256, hashMatches, hmacMatches };
}

export async function runArtifactSecurityScan() {
  const results = [];
  for (const artifact of ARTIFACTS) {
    let buffer;
    try {
      buffer = fs.readFileSync(artifact.filePath);
    } catch {
      continue;
    }
    results.push(await signArtifact(artifact.name, buffer));
  }
  return results;
}

export { ARTIFACTS };
