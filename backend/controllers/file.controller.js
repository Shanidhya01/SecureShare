import crypto from "crypto";
import bcrypt from "bcryptjs";
import streamifier from "streamifier";
import cloudinary from "../utils/cloudinary.js";
import File from "../models/File.js";
import { encryptBuffer } from "../utils/encrypt.js";
import fs from "fs";

const PUBLIC_KEY = fs.readFileSync("keys/public.pem", "utf8");

/* UPLOAD */
export const uploadFile = async (req, res) => {
  const { password } = req.body;
  if (!req.file) return res.status(400).json({ error: "No file" });

  const { encrypted, aesKey, iv } = encryptBuffer(req.file.buffer);

  const encryptedKey = crypto.publicEncrypt(
    { key: PUBLIC_KEY, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING },
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
    oneTime: true,
    expiresAt: new Date(Date.now() + 86400000)
  });

  res.json({ fileId: file._id });
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

  if (file.oneTime && file.downloadCount > 0)
    return res.status(403).json({ error: "Expired" });

  file.downloadCount++;
  file.logs.push({ ip: req.ip, time: new Date() });
  await file.save();

  const signedUrl = cloudinary.url(file.cloudinaryId, {
    resource_type: "raw",
    secure: true,
    sign_url: true
  });

  setTimeout(async () => {
    await cloudinary.uploader.destroy(file.cloudinaryId, { resource_type: "raw" });
    await File.findByIdAndDelete(file._id);
  }, 5000);

  res.json({ downloadUrl: signedUrl });
};

/* REVOKE */
export const revokeFile = async (req, res) => {
  const file = await File.findOne({ _id: req.params.id, owner: req.user.id });
  if (!file) return res.sendStatus(404);

  await cloudinary.uploader.destroy(file.cloudinaryId, { resource_type: "raw" });
  await file.deleteOne();

  res.json({ message: "Revoked" });
};

/* DASHBOARD */
export const getMyFiles = async (req, res) => {
  const files = await File.find({ owner: req.user.id }).sort({ createdAt: -1 });
  res.json(files);
};

/* LOGS */
export const getFileLogs = async (req, res) => {
  const file = await File.findOne({ _id: req.params.id, owner: req.user.id });
  if (!file) return res.sendStatus(404);
  res.json(file.logs);
};
