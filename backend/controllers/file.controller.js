import crypto from "crypto";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import streamifier from "streamifier";
import cloudinary from "../utils/cloudinary.js";
import File from "../models/File.js";
import User from "../models/User.js";
import Device from "../models/Device.js";
import { logSecurityEvent } from "../services/siem/siemLogger.js";
import ThreatScan from "../models/ThreatScan.js";
import DLPScan from "../models/DLPScan.js";
import { encryptBuffer } from "../utils/legacy/encrypt.js";
import { decryptBuffer } from "../utils/legacy/decrpyt.js";
import https from "https";
import fs from "fs";
import { getClientIp } from "../utils/getClientIp.js";
import { parseUserAgent } from "../utils/deviceContext.js";
import { resolveCountry } from "../utils/geoLookup.js";
import { evaluateDownloadPolicy, hasActivePolicy } from "../services/policyEngine.js";
import { runThreatScan } from "../services/threatScanService.js";
import { runDLPScan } from "../services/dlp/dlpEngine.js";

/* Phase 4: links a completed ThreatScan doc to the File it was ultimately used for, marking it
   consumed so the same clean scan result can't be replayed across multiple uploads. Returns the
   {scanStatus, riskLevel, quarantined} to mirror onto the File doc itself (requirement 7) - kept
   denormalized there so downloadFile's quarantine check never needs a second query/populate. */
const linkThreatScan = async (scanId, fileId) => {
  const scan = await ThreatScan.findByIdAndUpdate(scanId, { fileId, consumedByUpload: true }, { new: true });
  return scan;
};

/* Phase 5: same linking/replay-protection pattern as linkThreatScan, for the DLP scan. */
const linkDlpScan = async (dlpScanId, fileId) => {
  const scan = await DLPScan.findByIdAndUpdate(dlpScanId, { fileId, consumedByUpload: true }, { new: true });
  return scan;
};

/* Parses/sanitizes the optional Phase 3 access-policy JSON string sent with an upload into the
   File.policy subdocument shape. Returns undefined if no meaningful policy was provided, so
   Mongoose applies its schema defaults (an all-empty, "no restrictions" policy). */
const parsePolicyInput = (raw) => {
  if (!raw) return undefined;
  let parsed;
  try {
    parsed = typeof raw === "string" ? JSON.parse(raw) : raw;
  } catch {
    return undefined;
  }
  if (!parsed || typeof parsed !== "object") return undefined;

  const toStringArray = (v) =>
    Array.isArray(v) ? v.map((x) => String(x).trim()).filter(Boolean) : [];

  return {
    allowedCountries: toStringArray(parsed.allowedCountries),
    allowedIPs: toStringArray(parsed.allowedIPs),
    allowedDevices: toStringArray(parsed.allowedDevices),
    businessHours: {
      enabled: !!parsed.businessHours?.enabled,
      startHour: Math.min(Math.max(parseInt(parsed.businessHours?.startHour) || 0, 0), 23),
      endHour: Math.min(Math.max(parseInt(parsed.businessHours?.endHour) || 24, 0), 24)
    },
    maxDevices: Math.max(parseInt(parsed.maxDevices) || 0, 0),
    requireApproval: !!parsed.requireApproval
  };
};

/* UPLOAD */
export const uploadFile = async (req, res) => {
  try {
    const { maxDownloads, expiryHours } = req.body;
    if (!req.file) return res.status(400).json({ error: "No file uploaded" });

    // Parse and validate maxDownloads (default: 1, range: 1-100)
    const parsedMaxDownloads = Math.min(Math.max(parseInt(maxDownloads) || 1, 1), 100);

    // Parse and validate expiryHours (default: 24, range: 1-720 hours = 30 days)
    const parsedExpiryHours = Math.min(Math.max(parseInt(expiryHours) || 24, 1), 720);
    const expiryMs = parsedExpiryHours * 60 * 60 * 1000;

    if (!process.env.CLOUDINARY_CLOUD_NAME || !process.env.CLOUDINARY_API_KEY || !process.env.CLOUDINARY_API_SECRET) {
      return res.status(500).json({ error: "Cloudinary not configured (missing env vars)" });
    }

    const policy = parsePolicyInput(req.body.policy);
    const opts = { parsedMaxDownloads, parsedExpiryHours, expiryMs, policy };

    const encryptionVersion = parseInt(req.body.encryptionVersion) === 2 ? 2 : 1;
    if (encryptionVersion === 2) return uploadFileV2(req, res, opts);
    return uploadFileV1(req, res, opts);
  } catch (err) {
    console.error("Upload error:", err);
    const message = err?.message || "Upload failed";
    res.status(500).json({ error: message });
  }
};

/* UPLOAD - legacy (encryptionVersion 1): server encrypts with the global RSA keypair. Unchanged
   behavior, kept only for backward compatibility; new clients always send encryptionVersion=2. */
const uploadFileV1 = async (req, res, { parsedMaxDownloads, expiryMs, policy }) => {
  const { password } = req.body;

  // Load RSA public key from env or filesystem
  let publicKey = process.env.RSA_PUBLIC_KEY;
  if (!publicKey && process.env.RSA_PUBLIC_KEY_BASE64) {
    try {
      publicKey = Buffer.from(process.env.RSA_PUBLIC_KEY_BASE64, "base64").toString("utf8");
    } catch (e) {
      return res.status(500).json({ error: "Invalid RSA_PUBLIC_KEY_BASE64" });
    }
  }
  if (!publicKey) {
    try {
      publicKey = fs.readFileSync("keys/public.pem", "utf8");
    } catch (err) {
      return res.status(500).json({ error: "Public key not found. Set RSA_PUBLIC_KEY env or include keys/public.pem" });
    }
  }

  // Phase 4: the legacy v1 flow already receives plaintext server-side (that's the whole point
  // of v1's server-side encryption), so it can run a genuine, meaningful malware scan inline -
  // no separate pre-encryption round trip needed like v2's zero-knowledge flow requires.
  const scanResult = await runThreatScan(req.file.buffer, {
    originalFilename: req.file.originalname,
    claimedMimeType: req.file.mimetype
  });

  // Phase 5: DLP runs inline right after the malware scan and before encryption, same reasoning
  // as above - v1 already has plaintext server-side. A "block" decision refuses the upload
  // outright before anything is encrypted/stored. "require_approval" has no synchronous
  // confirmation step in this single-request legacy flow, so it's also refused here - use the
  // v2 (zero-knowledge) upload flow, which supports POST /api/dlp/scans/:id/acknowledge, if you
  // need to explicitly override a require_approval finding.
  const dlpResult = runDLPScan(req.file.buffer, {
    originalFilename: req.file.originalname,
    claimedMimeType: req.file.mimetype
  });

  if (dlpResult.decision === "block" || dlpResult.decision === "require_approval") {
    const dlpScan = await DLPScan.create({ owner: req.user.id, ...dlpResult });
    logSecurityEvent({
      owner: req.user.id,
      type: "dlp_blocked",
      message: `Upload blocked: sensitive data detected (${dlpScan.matchedPatterns.join(", ") || dlpScan.severity + " risk"})`,
      filename: dlpScan.originalFilename,
      ip: req.headers["x-client-ip"] || req.ip
    }).catch((e) => console.error("Failed to record security event:", e));

    return res.status(422).json({
      error: "Upload blocked: sensitive data detected by DLP scan",
      dlpScanId: dlpScan._id,
      severity: dlpScan.severity,
      matchedPatterns: dlpScan.matchedPatterns
    });
  }

  const { encrypted, aesKey, iv } = encryptBuffer(req.file.buffer);

  const encryptedKey = crypto.publicEncrypt(
    { key: publicKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING },
    aesKey
  ).toString("base64");

  const uploadResult = await new Promise((resolve, reject) => {
    const stream = cloudinary.uploader.upload_stream(
      { resource_type: "raw" },
      (e, r) => e ? reject(e) : resolve(r)
    );
    streamifier.createReadStream(encrypted).pipe(stream);
  });

  const file = await File.create({
    filename: req.file.originalname,
    cloudinaryId: uploadResult.public_id,
    encryptionVersion: 1,
    encryptedKey,
    iv: iv.toString("base64"),
    passwordHash: password ? await bcrypt.hash(password, 10) : null,
    owner: req.user.id,
    oneTime: parsedMaxDownloads === 1,
    maxDownloads: parsedMaxDownloads,
    expiresAt: new Date(Date.now() + expiryMs),
    scanStatus: scanResult.scanStatus,
    riskLevel: scanResult.riskLevel,
    quarantined: scanResult.quarantined,
    dlpStatus: dlpResult.supported ? dlpResult.scanStatus : "skipped",
    dlpRisk: dlpResult.severity,
    dlpDecision: dlpResult.decision,
    policy
  });

  const scan = await ThreatScan.create({ owner: req.user.id, fileId: file._id, consumedByUpload: true, ...scanResult });
  file.scanId = scan._id;

  const dlpScan = await DLPScan.create({ owner: req.user.id, fileId: file._id, consumedByUpload: true, ...dlpResult });
  file.dlpScanId = dlpScan._id;

  await file.save();

  if (dlpResult.decision === "warn" && dlpResult.findings.length > 0) {
    logSecurityEvent({
      owner: req.user.id,
      type: "dlp_warning",
      message: `Sensitive data detected in "${file.filename}": ${dlpResult.matchedPatterns.join(", ")}`,
      file: file._id,
      filename: file.filename
    }).catch((e) => console.error("Failed to record security event:", e));
  }

  if (scan.quarantined) {
    logSecurityEvent({
      owner: req.user.id,
      type: "file_quarantined",
      message: `Upload quarantined: ${scan.riskLevel} risk`,
      file: file._id,
      filename: file.filename
    }).catch((e) => console.error("Failed to record security event:", e));
  }

  logSecurityEvent({
    owner: req.user.id,
    type: "upload",
    message: `Uploaded "${file.filename}"`,
    file: file._id,
    filename: file.filename
  }).catch((e) => console.error("Failed to record security event:", e));

  res.json({ fileId: file._id });
};

/* UPLOAD - v2 (client-side E2E): the browser has already encrypted req.file.buffer with AES-256-GCM
   and wrapped the AES key with RSA-OAEP/password-derived keys. The server performs no cryptography
   here at all — it only stores the ciphertext and the already-wrapped key material. */
const uploadFileV2 = async (req, res, { parsedMaxDownloads, expiryMs, policy }) => {
  const {
    iv,
    mimeType,
    algorithm,
    wrappedOwnerKey,
    wrappedPasswordKey,
    keySalt,
    keyIterations,
    passwordKeyIvHint,
    signature,
    fileHash,
    hashAlgorithm,
    signatureAlgorithm,
    signedAt,
    scanId,
    dlpScanId
  } = req.body;

  if (!iv || !wrappedOwnerKey) {
    return res.status(400).json({ error: "Missing iv or wrappedOwnerKey for encryptionVersion 2 upload" });
  }

  // All-or-nothing: if any password-wrap field is present, all must be.
  const hasPasswordFields = wrappedPasswordKey || keySalt || passwordKeyIvHint;
  if (hasPasswordFields && !(wrappedPasswordKey && keySalt && passwordKeyIvHint)) {
    return res.status(400).json({ error: "Incomplete password-protected key material" });
  }

  // Phase 2 signing is optional (preserves compatibility with pre-Phase-2 clients) but all-or-nothing
  // when present - a signature without its hash/algorithm metadata can't be verified meaningfully.
  const hasSignatureFields = signature || fileHash || hashAlgorithm || signatureAlgorithm;
  if (hasSignatureFields && !(signature && fileHash && hashAlgorithm && signatureAlgorithm)) {
    return res.status(400).json({ error: "Incomplete signature metadata" });
  }

  // Phase 4: every new upload must reference a completed pre-encryption scan (POST /api/threats/
  // scan) - this is what makes malware scanning possible at all in a zero-knowledge system (see
  // threatScanService.js). Not required for encryptionVersion 1, which scans inline instead since
  // it already has plaintext server-side. A scan can only back a single upload (replay protection).
  if (!scanId) {
    return res.status(400).json({ error: "Missing scanId - scan the file with POST /api/threats/scan before uploading" });
  }
  const scan = await ThreatScan.findById(scanId);
  if (!scan || String(scan.owner) !== String(req.user.id)) {
    return res.status(400).json({ error: "Invalid scanId" });
  }
  if (scan.consumedByUpload) {
    return res.status(400).json({ error: "This scan result has already been used for another upload" });
  }

  // Phase 5: same requirement for a DLP scan, run after the malware scan and before encryption
  // (POST /api/dlp/scan) - see services/dlp/dlpEngine.js. A "block" decision refuses the upload
  // outright; a "require_approval" decision refuses unless the owner has explicitly acknowledged
  // it first (POST /api/dlp/scans/:id/acknowledge).
  if (!dlpScanId) {
    return res.status(400).json({ error: "Missing dlpScanId - scan the file with POST /api/dlp/scan before uploading" });
  }
  const dlpScan = await DLPScan.findById(dlpScanId);
  if (!dlpScan || String(dlpScan.owner) !== String(req.user.id)) {
    return res.status(400).json({ error: "Invalid dlpScanId" });
  }
  if (dlpScan.consumedByUpload) {
    return res.status(400).json({ error: "This DLP scan result has already been used for another upload" });
  }
  if (dlpScan.decision === "block") {
    return res.status(422).json({
      error: "Upload blocked: sensitive data detected by DLP scan",
      severity: dlpScan.severity,
      matchedPatterns: dlpScan.matchedPatterns
    });
  }
  if (dlpScan.decision === "require_approval" && !dlpScan.acknowledged) {
    return res.status(422).json({
      error: "Upload requires approval: sensitive data detected by DLP scan. Acknowledge via POST /api/dlp/scans/:id/acknowledge to proceed.",
      dlpScanId: dlpScan._id,
      severity: dlpScan.severity,
      matchedPatterns: dlpScan.matchedPatterns
    });
  }

  const owner = await User.findById(req.user.id).select("publicKey");
  if (!owner?.publicKey) {
    return res.status(400).json({ error: "Set up your encryption key before uploading files" });
  }

  const uploadResult = await new Promise((resolve, reject) => {
    const stream = cloudinary.uploader.upload_stream(
      { resource_type: "raw" },
      (e, r) => e ? reject(e) : resolve(r)
    );
    streamifier.createReadStream(req.file.buffer).pipe(stream);
  });

  const file = await File.create({
    filename: req.file.originalname,
    originalFilename: req.file.originalname,
    cloudinaryId: uploadResult.public_id,
    encryptionVersion: 2,
    mimeType,
    algorithm: algorithm || "AES-256-GCM",
    iv,
    wrappedOwnerKey,
    wrappedPasswordKey: wrappedPasswordKey || undefined,
    keySalt: keySalt || undefined,
    keyIterations: keyIterations ? parseInt(keyIterations) : undefined,
    passwordKeyIvHint: passwordKeyIvHint || undefined,
    signature: signature || undefined,
    fileHash: fileHash || undefined,
    hashAlgorithm: hashAlgorithm || undefined,
    signatureAlgorithm: signatureAlgorithm || undefined,
    signedAt: signedAt ? new Date(signedAt) : undefined,
    owner: req.user.id,
    oneTime: parsedMaxDownloads === 1,
    maxDownloads: parsedMaxDownloads,
    expiresAt: new Date(Date.now() + expiryMs),
    scanId: scan._id,
    scanStatus: scan.scanStatus,
    riskLevel: scan.riskLevel,
    quarantined: scan.quarantined,
    dlpScanId: dlpScan._id,
    dlpStatus: dlpScan.supported ? dlpScan.scanStatus : "skipped",
    dlpRisk: dlpScan.severity,
    dlpDecision: dlpScan.decision,
    policy
  });

  await linkThreatScan(scan._id, file._id);
  await linkDlpScan(dlpScan._id, file._id);

  if (scan.quarantined) {
    logSecurityEvent({
      owner: req.user.id,
      type: "file_quarantined",
      message: `Upload quarantined: ${scan.riskLevel} risk`,
      file: file._id,
      filename: file.filename
    }).catch((e) => console.error("Failed to record security event:", e));
  }

  if (dlpScan.decision === "warn" || dlpScan.decision === "require_approval") {
    logSecurityEvent({
      owner: req.user.id,
      type: dlpScan.decision === "warn" ? "dlp_warning" : "dlp_sensitive_data_detected",
      message: `Sensitive data detected in "${file.filename}": ${dlpScan.matchedPatterns.join(", ")}`,
      file: file._id,
      filename: file.filename
    }).catch((e) => console.error("Failed to record security event:", e));
  }

  logSecurityEvent({
    owner: req.user.id,
    type: "upload",
    message: `Uploaded "${file.filename}"`,
    file: file._id,
    filename: file.filename
  }).catch((e) => console.error("Failed to record security event:", e));

  res.json({ fileId: file._id });
};

/* METADATA - lightweight, no auth, no download-count bump, no log write. Lets the frontend fetch
   everything it needs to unwrap/decrypt a v2 file before pulling the (potentially large) ciphertext. */
export const getFileMeta = async (req, res) => {
  const file = await File.findById(req.params.id).populate("owner", "signingPublicKey");
  if (!file) return res.status(404).json({ error: "not_found" });
  if (file.revoked) return res.status(410).json({ error: "revoked" });
  if (file.expiresAt && file.expiresAt.getTime() < Date.now()) {
    return res.status(410).json({ error: "expired" });
  }

  const meta = {
    encryptionVersion: file.encryptionVersion,
    filename: file.filename,
    mimeType: file.mimeType || null,
    hasPassword: !!(file.passwordHash || file.wrappedPasswordKey),
    oneTime: file.oneTime,
    maxDownloads: file.maxDownloads,
    downloadCount: file.downloadCount,
    limitReached: file.downloadCount >= file.maxDownloads,
    // Phase 3: only a boolean flag is exposed here (never the actual allowed countries/IPs/
    // devices) so an anonymous requester can't enumerate a file's access rules from /meta.
    hasPolicy: hasActivePolicy(file.policy),
    // Phase 4: exposed so the frontend can show a clear "this file was quarantined" message
    // instead of attempting a download that the server will reject anyway.
    scanStatus: file.scanStatus,
    riskLevel: file.riskLevel,
    quarantined: file.quarantined
  };

  if (file.encryptionVersion === 2) {
    Object.assign(meta, {
      iv: file.iv,
      algorithm: file.algorithm || "AES-256-GCM",
      originalFilename: file.originalFilename || file.filename,
      wrappedOwnerKey: file.wrappedOwnerKey,
      wrappedPasswordKey: file.wrappedPasswordKey || null,
      keySalt: file.keySalt || null,
      keyIterations: file.keyIterations || null,
      passwordKeyIvHint: file.passwordKeyIvHint || null,
      // Phase 2: signature is only present/verifiable if the uploader signed this file AND
      // still has a signing public key on record. Absence of either means "unsigned" - the
      // download flow treats that as a compatibility case, not an error.
      signature: file.signature || null,
      fileHash: file.fileHash || null,
      hashAlgorithm: file.hashAlgorithm || null,
      signatureAlgorithm: file.signatureAlgorithm || null,
      signedAt: file.signedAt || null,
      ownerSigningPublicKey: file.owner?.signingPublicKey || null
    });
  }

  res.json(meta);
};

/* Builds the Zero Trust evaluation context for a single download request. The download route is
   public (no auth middleware - share links must work for anonymous recipients), so any user
   identity here is best-effort: an Authorization header is decoded if present, but a missing or
   invalid one just means "anonymous" rather than a rejected request. */
const buildDownloadContext = async (req, file) => {
  const ip = getClientIp(req);
  const country = resolveCountry(req);
  const deviceId = typeof req.headers["x-device-id"] === "string" ? req.headers["x-device-id"] : undefined;
  const { browser, operatingSystem } = parseUserAgent(req.headers["user-agent"]);
  const time = new Date();

  let userId;
  const authHeader = req.headers.authorization;
  if (authHeader) {
    try {
      const decoded = jwt.verify(authHeader.split(" ")[1], process.env.JWT_SECRET);
      userId = decoded.id;
    } catch {
      // Best-effort only: an absent/invalid/expired token just means "anonymous" for policy
      // purposes, since the download route itself doesn't require authentication.
    }
  }

  const context = { ip, country, deviceId, browser, operatingSystem, time, userId };

  if (hasActivePolicy(file.policy)) {
    if (file.policy.maxDevices > 0) {
      context.knownDeviceIds = [
        ...new Set(file.logs.filter((l) => l.decision !== "deny" && l.deviceId).map((l) => l.deviceId))
      ];
    }
    if (file.policy.requireApproval && userId && deviceId) {
      const device = await Device.findOne({ owner: userId, deviceId, trusted: true, revoked: false });
      context.deviceTrusted = !!device;
    }
  }

  return context;
};

/* DOWNLOAD */
export const downloadFile = async (req, res) => {
  const file = await File.findById(req.params.id);

  if (!file) return res.status(404).json({ error: "not_found" });
  if (file.revoked) return res.status(410).json({ error: "revoked" });
  if (file.expiresAt && file.expiresAt.getTime() < Date.now()) {
    return res.status(410).json({ error: "expired" });
  }

  // Check if max downloads exceeded
  if (file.downloadCount >= file.maxDownloads) {
    return res.status(403).json({ error: "download_limit_reached" });
  }

  const context = await buildDownloadContext(req, file);

  // Phase 4: quarantine is checked before the Zero Trust policy engine and unconditionally -
  // there is no policy override or per-file config that can un-block a quarantined file except
  // the owner explicitly releasing it (POST /api/threats/quarantine/:id/release).
  if (file.quarantined) {
    file.logs.push({
      ip: context.ip,
      time: context.time,
      deviceId: context.deviceId,
      browser: context.browser,
      operatingSystem: context.operatingSystem,
      country: context.country,
      decision: "deny",
      denialReason: "File is quarantined due to a threat scan detection",
      scanStatus: file.scanStatus,
      riskLevel: file.riskLevel
    });
    await file.save();

    logSecurityEvent({
      owner: file.owner,
      type: "download_denied",
      message: `Blocked download of quarantined file (${file.riskLevel} risk)`,
      file: file._id,
      filename: file.filename,
      deviceId: context.deviceId,
      ip: context.ip,
      country: context.country,
      category: "THREAT",
      severity: "HIGH",
      metadata: { riskLevel: file.riskLevel }
    }).catch((e) => console.error("Failed to record security event:", e));

    return res.status(403).json({ error: "quarantined", riskLevel: file.riskLevel });
  }

  // Zero Trust (Phase 3): evaluate the file's access policy (if any) before serving a single
  // byte. A file with no policy configured always evaluates to "allow" (see policyEngine.js) -
  // this is what keeps every pre-Phase-3 file working exactly as before.
  const policyDecision = evaluateDownloadPolicy(file.policy, context);

  if (policyDecision.decision === "deny") {
    file.logs.push({
      ip: context.ip,
      time: context.time,
      deviceId: context.deviceId,
      browser: context.browser,
      operatingSystem: context.operatingSystem,
      country: context.country,
      decision: "deny",
      denialReason: policyDecision.reason,
      scanStatus: file.scanStatus,
      riskLevel: file.riskLevel
    });
    await file.save();

    logSecurityEvent({
      owner: file.owner,
      type: "download_denied",
      message: policyDecision.reason,
      file: file._id,
      filename: file.filename,
      deviceId: context.deviceId,
      ip: context.ip,
      country: context.country,
      siemType: "POLICY_VIOLATION",
      category: "ZERO_TRUST"
    }).catch((e) => console.error("Failed to record security event:", e));

    return res.status(403).json({ error: "policy_denied", reason: policyDecision.reason });
  }

  if (file.encryptionVersion === 2) return downloadFileV2(req, res, file, context);
  return downloadFileV1(req, res, file, context);
};

/* Shared cleanup: destroy the Cloudinary object and auto-revoke once the download limit is hit. */
const finalizeDownload = async (file) => {
  try {
    await cloudinary.uploader.destroy(file.cloudinaryId, { resource_type: "raw" });
    const latest = await File.findById(file._id);
    if (latest && latest.downloadCount >= latest.maxDownloads) {
      latest.revoked = true; // prevent further downloads
      await latest.save();
    }
  } catch (e) {
    console.error("Cleanup error:", e);
  }
};

/* DOWNLOAD - legacy (encryptionVersion 1): server decrypts and streams plaintext. Unchanged behavior,
   kept only for backward compatibility with files uploaded before the client-side E2E (v2) migration. */
const downloadFileV1 = async (req, res, file, context) => {
  const { password } = req.query;

  if (file.passwordHash) {
    const ok = await bcrypt.compare(password || "", file.passwordHash);
    if (!ok) return res.status(403).json({ error: "Wrong password" });
  }

  file.downloadCount++;

  // Log download with IP and optional user email (from query)
  const userEmail = typeof req.query.email === "string" ? req.query.email : undefined;
  console.log("Download log - IP:", context.ip, "| Email:", userEmail || "not provided");
  file.logs.push({
    ip: context.ip,
    userEmail,
    time: context.time,
    deviceId: context.deviceId,
    browser: context.browser,
    operatingSystem: context.operatingSystem,
    country: context.country,
    decision: "allow",
    scanStatus: file.scanStatus,
    riskLevel: file.riskLevel
  });
  await file.save();

  logSecurityEvent({
    owner: file.owner,
    type: "download_allowed",
    message: `Downloaded "${file.filename}"`,
    file: file._id,
    filename: file.filename,
    deviceId: context.deviceId,
    ip: context.ip,
    country: context.country
  }).catch((e) => console.error("Failed to record security event:", e));

  try {
    // Resolve signed URL to fetch encrypted bytes from Cloudinary
    const signedUrl = cloudinary.url(file.cloudinaryId, {
      resource_type: "raw",
      secure: true,
      sign_url: true,
    });

    const encryptedData = await new Promise((resolve, reject) => {
      https.get(signedUrl, (r) => {
        if (r.statusCode && r.statusCode >= 400) {
          reject(new Error(`Cloudinary download failed with status ${r.statusCode}`));
          return;
        }
        const chunks = [];
        r.on("data", (c) => chunks.push(c));
        r.on("end", () => resolve(Buffer.concat(chunks)));
      }).on("error", reject);
    });

    // Decrypt AES key using RSA private key
    // Load RSA private key from env or filesystem
    let privateKey = process.env.RSA_PRIVATE_KEY;
    if (!privateKey && process.env.RSA_PRIVATE_KEY_BASE64) {
      try {
        privateKey = Buffer.from(process.env.RSA_PRIVATE_KEY_BASE64, "base64").toString("utf8");
      } catch (e) {
        return res.status(500).json({ error: "Invalid RSA_PRIVATE_KEY_BASE64" });
      }
    }
    if (!privateKey) {
      try {
        privateKey = fs.readFileSync("keys/private.pem", "utf8");
      } catch (e) {
        return res.status(500).json({ error: "Private key not found. Set RSA_PRIVATE_KEY env or include keys/private.pem" });
      }
    }

    const encryptedKeyBuf = Buffer.from(file.encryptedKey, "base64");
    const iv = Buffer.from(file.iv, "base64");
    const aesKey = crypto.privateDecrypt(
      { key: privateKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING },
      encryptedKeyBuf
    );

    // Decrypt file content
    const originalData = decryptBuffer(encryptedData, aesKey, iv);

    // Stream decrypted file to client as attachment
    res.setHeader("Content-Type", "application/octet-stream");
    res.setHeader(
      "Content-Disposition",
      `attachment; filename="${file.filename}"`
    );
    res.send(originalData);

    // Cleanup after sending
    res.on("finish", () => finalizeDownload(file));
  } catch (err) {
    console.error("Download decrypt error:", err);
    res.status(500).json({ error: err?.message || "Failed to decrypt file" });
  }
};

/* DOWNLOAD - v2 (client-side E2E): server never decrypts, it just streams the ciphertext through.
   The browser fetches this alongside GET /file/:id/meta (for iv/wrapped keys) and decrypts locally. */
const downloadFileV2 = async (req, res, file, context) => {
  file.downloadCount++;

  const userEmail = typeof req.query.email === "string" ? req.query.email : undefined;
  file.logs.push({
    ip: context.ip,
    userEmail,
    time: context.time,
    deviceId: context.deviceId,
    browser: context.browser,
    operatingSystem: context.operatingSystem,
    country: context.country,
    decision: "allow",
    scanStatus: file.scanStatus,
    riskLevel: file.riskLevel
  });
  await file.save();

  logSecurityEvent({
    owner: file.owner,
    type: "download_allowed",
    message: `Downloaded "${file.filename}"`,
    file: file._id,
    filename: file.filename,
    deviceId: context.deviceId,
    ip: context.ip,
    country: context.country
  }).catch((e) => console.error("Failed to record security event:", e));

  try {
    const signedUrl = cloudinary.url(file.cloudinaryId, {
      resource_type: "raw",
      secure: true,
      sign_url: true,
    });

    const encryptedData = await new Promise((resolve, reject) => {
      https.get(signedUrl, (r) => {
        if (r.statusCode && r.statusCode >= 400) {
          reject(new Error(`Cloudinary download failed with status ${r.statusCode}`));
          return;
        }
        const chunks = [];
        r.on("data", (c) => chunks.push(c));
        r.on("end", () => resolve(Buffer.concat(chunks)));
      }).on("error", reject);
    });

    res.setHeader("Content-Type", "application/octet-stream");
    res.setHeader(
      "Content-Disposition",
      `attachment; filename="${file.filename}.enc"`
    );
    res.send(encryptedData);

    res.on("finish", () => finalizeDownload(file));
  } catch (err) {
    console.error("Download fetch error:", err);
    res.status(500).json({ error: err?.message || "Failed to fetch encrypted file" });
  }
};

/* REVOKE */
export const revokeFile = async (req, res) => {
  const file = await File.findOne({ _id: req.params.id, owner: req.user.id });
  if (!file) return res.sendStatus(404);

  try {
    await cloudinary.uploader.destroy(file.cloudinaryId, { resource_type: "raw" });
  } catch (e) {
    // ignore destroy errors; proceed to mark revoked
  }

  file.revoked = true;
  await file.save();

  res.json({ message: "Revoked" });
};

/* POLICY (Phase 3, owner-only) - view/edit a file's Zero Trust access policy. */
export const getFilePolicy = async (req, res) => {
  const file = await File.findOne({ _id: req.params.id, owner: req.user.id }).select("policy");
  if (!file) return res.sendStatus(404);
  res.json(file.policy);
};

export const updateFilePolicy = async (req, res) => {
  const file = await File.findOne({ _id: req.params.id, owner: req.user.id });
  if (!file) return res.sendStatus(404);

  const policy = parsePolicyInput(req.body.policy ?? req.body);
  if (!policy) return res.status(400).json({ error: "Invalid policy payload" });

  file.policy = policy;
  await file.save();

  res.json(file.policy);
};

/* DASHBOARD */
export const getMyFiles = async (req, res) => {
  const files = await File
    .find({ owner: req.user.id })
    .sort({ createdAt: -1 })
    .populate("owner", "email name");
  res.json(files);
};

// Get all files (visible to any authenticated user)
export const getAllFiles = async (req, res) => {
  const files = await File
    .find({})
    .sort({ createdAt: -1 })
    .populate("owner", "email name");
  res.json(files);
};

/* LOGS */
export const getFileLogs = async (req, res) => {
  const file = await File.findOne({ _id: req.params.id, owner: req.user.id });
  if (!file) return res.sendStatus(404);
  res.json(file.logs);
};

/* DELETE */
export const deleteFile = async (req, res) => {
  const file = await File.findOne({ _id: req.params.id, owner: req.user.id });
  if (!file) return res.sendStatus(404);

  try {
    // Try to delete from Cloudinary (ignore if already deleted)
    await cloudinary.uploader.destroy(file.cloudinaryId, { resource_type: "raw" });
  } catch (e) {
    console.error("Cloudinary delete error:", e);
    // Continue with DB deletion even if Cloudinary fails
  }

  // Permanently delete from database
  await File.findByIdAndDelete(req.params.id);

  res.json({ message: "File deleted permanently" });
};
