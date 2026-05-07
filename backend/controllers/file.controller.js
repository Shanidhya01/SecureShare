import crypto from "crypto";
import bcrypt from "bcryptjs";
import streamifier from "streamifier";
import cloudinary from "../utils/cloudinary.js";
import File from "../models/File.js";
import { encryptBuffer } from "../utils/encrypt.js";
import { decryptBuffer } from "../utils/decrpyt.js";
import https from "https";
import fs from "fs";
import { getClientIp } from "../utils/getClientIp.js";

/* UPLOAD */
export const uploadFile = async (req, res) => {
  try {
    const { password, maxDownloads, expiryHours } = req.body;
    if (!req.file) return res.status(400).json({ error: "No file uploaded" });

    // Parse and validate maxDownloads (default: 1, range: 1-100)
    const parsedMaxDownloads = Math.min(Math.max(parseInt(maxDownloads) || 1, 1), 100);

    // Parse and validate expiryHours (default: 24, range: 1-720 hours = 30 days)
    const parsedExpiryHours = Math.min(Math.max(parseInt(expiryHours) || 24, 1), 720);
    const expiryMs = parsedExpiryHours * 60 * 60 * 1000;

    if (!process.env.CLOUDINARY_CLOUD_NAME || !process.env.CLOUDINARY_API_KEY || !process.env.CLOUDINARY_API_SECRET) {
      return res.status(500).json({ error: "Cloudinary not configured (missing env vars)" });
    }

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
      encryptedKey,
      iv: iv.toString("base64"),
      passwordHash: password ? await bcrypt.hash(password, 10) : null,
      owner: req.user.id,
      oneTime: parsedMaxDownloads === 1,
      maxDownloads: parsedMaxDownloads,
      expiresAt: new Date(Date.now() + expiryMs)
    });

    res.json({ fileId: file._id });
  } catch (err) {
    console.error("Upload error:", err);
    const message = err?.message || "Upload failed";
    res.status(500).json({ error: message });
  }
};

/* DOWNLOAD */
export const downloadFile = async (req, res) => {
  const { password } = req.query;
  const file = await File.findById(req.params.id);

  if (!file || file.revoked) return res.sendStatus(404);

  if (file.passwordHash) {
    const ok = await bcrypt.compare(password || "", file.passwordHash);
    if (!ok) return res.status(403).json({ error: "Wrong password" });
  }

  // Check if max downloads exceeded
  if (file.downloadCount >= file.maxDownloads) {
    return res.status(403).json({ error: "Download limit reached" });
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
    res.on("finish", async () => {
      try {
        await cloudinary.uploader.destroy(file.cloudinaryId, { resource_type: "raw" });
        // Keep record for history; mark as revoked if max downloads reached
        const latest = await File.findById(file._id);
        if (latest && latest.downloadCount >= latest.maxDownloads) {
          latest.revoked = true; // prevent further downloads
          await latest.save();
        }
      } catch (e) {
        console.error("Cleanup error:", e);
      }
    });
  } catch (err) {
    console.error("Download decrypt error:", err);
    res.status(500).json({ error: err?.message || "Failed to decrypt file" });
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
