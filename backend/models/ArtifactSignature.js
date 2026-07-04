import mongoose from "mongoose";

/**
 * Phase 12 (DevSecOps/Supply Chain): tamper-evidence record for a build artifact (here, the
 * package-lock.json files stand in for a real build artifact - there's no build pipeline producing
 * binaries in this project). `hmacSignature` is an HMAC-SHA256 over the hash, keyed with the app's
 * existing JWT_SECRET (see services/devsecops/artifactSecurity.js) - honestly an integrity/
 * tamper-detection mechanism, not a code-signing PKI certificate.
 */
const artifactSignatureSchema = new mongoose.Schema(
  {
    artifactName: { type: String, required: true },
    algorithm: { type: String, default: "sha256" },
    hash: { type: String, required: true },
    hmacSignature: { type: String, required: true },
    verified: { type: Boolean, default: false },
    verifiedAt: Date,
    status: { type: String, enum: ["valid", "tampered", "unsigned"], default: "unsigned" }
  },
  { timestamps: true }
);

artifactSignatureSchema.index({ artifactName: 1, createdAt: -1 });

export default mongoose.model("ArtifactSignature", artifactSignatureSchema);
