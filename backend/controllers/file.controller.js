import crypto from "crypto";
import bcrypt from "bcryptjs";
import streamifier from "streamifier";
import cloudinary from "../utils/cloudinary.js";
import File from "../models/File.js";
import User from "../models/User.js";
import { encryptBuffer } from "../utils/legacy/encrypt.js";
import { decryptBuffer } from "../utils/legacy/decrpyt.js";
import https from "https";
import fs from "fs";
import { getClientIp } from "../utils/getClientIp.js";

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

    const opts = { parsedMaxDownloads, parsedExpiryHours, expiryMs };

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
const uploadFileV1 = async (req, res, { parsedMaxDownloads, expiryMs }) => {
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
    expiresAt: new Date(Date.now() + expiryMs)
  });

  res.json({ fileId: file._id });
};

/* UPLOAD - v2 (client-side E2E): the browser has already encrypted req.file.buffer with AES-256-GCM
   and wrapped the AES key with RSA-OAEP/password-derived keys. The server performs no cryptography
   here at all — it only stores the ciphertext and the already-wrapped key material. */
const uploadFileV2 = async (req, res, { parsedMaxDownloads, expiryMs }) => {
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
    signedAt
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
    expiresAt: new Date(Date.now() + expiryMs)
  });

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
    limitReached: file.downloadCount >= file.maxDownloads
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

  if (file.encryptionVersion === 2) return downloadFileV2(req, res, file);
  return downloadFileV1(req, res, file);
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
const downloadFileV1 = async (req, res, file) => {
  const { password } = req.query;

  if (file.passwordHash) {
    const ok = await bcrypt.compare(password || "", file.passwordHash);
    if (!ok) return res.status(403).json({ error: "Wrong password" });
  }

  file.downloadCount++;

  // Log download with IP and optional user email (from query)
  const userEmail = typeof req.query.email === "string" ? req.query.email : undefined;
  const clientIp = getClientIp(req);
  console.log("Download log - IP:", clientIp, "| Email:", userEmail || "not provided");
  file.logs.push({ ip: clientIp, userEmail, time: new Date() });
  await file.save();

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
const downloadFileV2 = async (req, res, file) => {
  file.downloadCount++;

  const userEmail = typeof req.query.email === "string" ? req.query.email : undefined;
  const clientIp = getClientIp(req);
  file.logs.push({ ip: clientIp, userEmail, time: new Date() });
  await file.save();

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
