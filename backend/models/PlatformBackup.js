import mongoose from "mongoose";

/**
 * Phase 13 (Platform Operations) - PART 12: metadata record for each backup produced by
 * services/platform/backupManager.js. The backup archive itself is written to
 * backend/backups/<filename> (gitignored, same treatment as backend/uploads); this doc tracks
 * what was backed up, its checksum, and validation status. No destructive restore is implemented.
 */
const platformBackupSchema = new mongoose.Schema(
  {
    type: { type: String, enum: ["database", "configuration", "metadata", "audit", "full"], required: true },
    filename: String,
    format: { type: String, enum: ["zip", "json", "csv"], default: "zip" },
    sizeBytes: Number,
    checksum: String,
    collections: [String],
    status: { type: String, enum: ["completed", "failed"], default: "completed" },
    validated: { type: Boolean, default: false },
    validatedAt: Date,
    error: String,
    triggeredBy: { type: mongoose.Schema.Types.ObjectId, ref: "User" }
  },
  { timestamps: true }
);

export default mongoose.model("PlatformBackup", platformBackupSchema);
