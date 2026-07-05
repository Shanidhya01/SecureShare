/**
 * Phase 13 (Platform Operations) - PART 12: Backup Manager. Produces database/configuration/
 * metadata/audit backups as ZIP archives of JSON/CSV under backend/backups/ (gitignored, same
 * treatment as backend/uploads). Validation re-opens the archive and verifies the stored SHA-256
 * checksum - no destructive restore is implemented, per spec.
 */
import fs from "node:fs";
import fsp from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";
import archiver from "archiver";
import mongoose from "mongoose";
import PlatformBackup from "../../models/PlatformBackup.js";
import SecurityEvent from "../../models/SecurityEvent.js";
import { logSecurityEvent } from "../siem/siemLogger.js";

const BACKUP_DIR = path.resolve(process.cwd(), "backups");

const CONFIG_SAFE_ENV_KEYS = [
  "PORT", "NODE_ENV", "WEBAUTHN_RP_ID", "WEBAUTHN_RP_NAME", "WEBAUTHN_ORIGIN", "APP_BASE_URL",
  "CLAMAV_HOST", "CLAMAV_PORT", "CLOUD_MONITORED_DOMAINS", "REDIS_URL_CONFIGURED", "LOG_LEVEL"
];

const DATABASE_COLLECTIONS = [
  "users", "files", "devices", "securityevents", "incidents", "automationrules",
  "compliancecontrols", "complianceassessments", "cloudfindings", "devsecopsfindings"
];

async function ensureDir() {
  await fsp.mkdir(BACKUP_DIR, { recursive: true });
}

function sha256(filePath) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash("sha256");
    const stream = fs.createReadStream(filePath);
    stream.on("data", (d) => hash.update(d));
    stream.on("end", () => resolve(hash.digest("hex")));
    stream.on("error", reject);
  });
}

async function writeZip(filename, files) {
  await ensureDir();
  const filePath = path.join(BACKUP_DIR, filename);
  await new Promise((resolve, reject) => {
    const output = fs.createWriteStream(filePath);
    const archive = archiver("zip", { zlib: { level: 9 } });
    output.on("close", resolve);
    archive.on("error", reject);
    archive.pipe(output);
    for (const f of files) archive.append(f.content, { name: f.name });
    archive.finalize();
  });
  return filePath;
}

async function dumpCollections(collectionNames) {
  const dump = {};
  for (const name of collectionNames) {
    try {
      const docs = await mongoose.connection.db.collection(name).find({}).limit(5000).toArray();
      dump[name] = docs;
    } catch {
      dump[name] = [];
    }
  }
  return dump;
}

export async function createDatabaseBackup({ triggeredBy } = {}) {
  const dump = await dumpCollections(DATABASE_COLLECTIONS);
  const filename = `database-backup-${Date.now()}.zip`;
  const filePath = await writeZip(filename, [{ name: "database.json", content: JSON.stringify(dump, null, 2) }]);
  return finalizeBackup({ type: "database", filename, filePath, collections: DATABASE_COLLECTIONS, triggeredBy });
}

export async function createConfigurationBackup({ triggeredBy } = {}) {
  const safeConfig = Object.fromEntries(CONFIG_SAFE_ENV_KEYS.map((k) => [k, process.env[k] ?? null]));
  const filename = `configuration-backup-${Date.now()}.zip`;
  const filePath = await writeZip(filename, [{ name: "configuration.json", content: JSON.stringify(safeConfig, null, 2) }]);
  return finalizeBackup({ type: "configuration", filename, filePath, triggeredBy });
}

export async function createMetadataBackup({ triggeredBy } = {}) {
  const [fileCount, userCount, deviceCount] = await Promise.all([
    mongoose.connection.db.collection("files").countDocuments().catch(() => 0),
    mongoose.connection.db.collection("users").countDocuments().catch(() => 0),
    mongoose.connection.db.collection("devices").countDocuments().catch(() => 0)
  ]);
  const metadata = { generatedAt: new Date(), counts: { files: fileCount, users: userCount, devices: deviceCount } };
  const filename = `metadata-backup-${Date.now()}.zip`;
  const filePath = await writeZip(filename, [{ name: "metadata.json", content: JSON.stringify(metadata, null, 2) }]);
  return finalizeBackup({ type: "metadata", filename, filePath, triggeredBy });
}

export async function createAuditBackup({ triggeredBy } = {}) {
  const events = await SecurityEvent.find().sort({ createdAt: -1 }).limit(10000).lean();
  const csvHeader = "type,siemType,severity,category,message,createdAt\n";
  const csvRows = events
    .map((e) => [e.type, e.siemType || "", e.severity || "", e.category || "", (e.message || "").replace(/"/g, "'"), new Date(e.createdAt).toISOString()])
    .map((r) => r.map((v) => `"${v}"`).join(","))
    .join("\n");
  const filename = `audit-backup-${Date.now()}.zip`;
  const filePath = await writeZip(filename, [
    { name: "audit.json", content: JSON.stringify(events, null, 2) },
    { name: "audit.csv", content: csvHeader + csvRows }
  ]);
  return finalizeBackup({ type: "audit", filename, filePath, collections: ["securityevents"], triggeredBy });
}

async function finalizeBackup({ type, filename, filePath, collections, triggeredBy }) {
  try {
    const stats = await fsp.stat(filePath);
    const checksum = await sha256(filePath);
    const backup = await PlatformBackup.create({
      type,
      filename,
      format: "zip",
      sizeBytes: stats.size,
      checksum,
      collections,
      status: "completed",
      triggeredBy
    });
    await logSecurityEvent({
      owner: triggeredBy,
      type: "backup_completed",
      message: `Platform ${type} backup completed (${filename})`,
      metadata: { type, filename, sizeBytes: stats.size }
    }).catch(() => {});
    return backup;
  } catch (err) {
    const backup = await PlatformBackup.create({ type, filename, status: "failed", error: err.message, triggeredBy });
    await logSecurityEvent({
      owner: triggeredBy,
      type: "backup_failed",
      message: `Platform ${type} backup failed: ${err.message}`,
      metadata: { type, error: err.message }
    }).catch(() => {});
    return backup;
  }
}

export async function runBackup({ type, triggeredBy } = {}) {
  switch (type) {
    case "database":
      return createDatabaseBackup({ triggeredBy });
    case "configuration":
      return createConfigurationBackup({ triggeredBy });
    case "metadata":
      return createMetadataBackup({ triggeredBy });
    case "audit":
      return createAuditBackup({ triggeredBy });
    case "full": {
      const [db, config, meta, audit] = await Promise.all([
        createDatabaseBackup({ triggeredBy }),
        createConfigurationBackup({ triggeredBy }),
        createMetadataBackup({ triggeredBy }),
        createAuditBackup({ triggeredBy })
      ]);
      return { database: db, configuration: config, metadata: meta, audit };
    }
    default:
      throw new Error(`Unknown backup type: ${type}`);
  }
}

export async function listBackups() {
  return PlatformBackup.find().sort({ createdAt: -1 }).limit(100).lean();
}

/** Re-hashes the archive on disk and compares against the stored checksum - no restore. */
export async function validateBackup(backupId) {
  const backup = await PlatformBackup.findById(backupId);
  if (!backup) throw new Error("Backup not found");
  const filePath = path.join(BACKUP_DIR, backup.filename);
  try {
    const exists = fs.existsSync(filePath);
    if (!exists) throw new Error("Backup file missing on disk");
    const checksum = await sha256(filePath);
    const valid = checksum === backup.checksum;
    backup.validated = valid;
    backup.validatedAt = new Date();
    if (!valid) backup.error = "Checksum mismatch";
    await backup.save();
    return { valid, backup };
  } catch (err) {
    backup.validated = false;
    backup.validatedAt = new Date();
    backup.error = err.message;
    await backup.save();
    return { valid: false, backup, error: err.message };
  }
}
