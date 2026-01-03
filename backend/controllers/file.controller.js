import fs from "fs";
import path from "path";
import crypto from "crypto";
import multer from "multer";
import File from "../models/File.js";
import { encryptBuffer } from "../utils/encrypt.js";

// --------------------
// Ensure uploads folder exists
// --------------------
const UPLOAD_DIR = "uploads";
if (!fs.existsSync(UPLOAD_DIR)) {
  fs.mkdirSync(UPLOAD_DIR);
}

// --------------------
// Multer with security checks
// --------------------
const upload = multer({
  limits: {
    fileSize: 5 * 1024 * 1024 // 5 MB limit
  },
  fileFilter: (req, file, cb) => {
    const allowedTypes = [
      "image/png",
      "image/jpeg",
      "application/pdf",
      "text/plain"
    ];

    if (!allowedTypes.includes(file.mimetype)) {
      cb(new Error("Invalid file type"), false);
    } else {
      cb(null, true);
    }
  }
});

export const uploadMiddleware = upload.single("file");

// --------------------
// Load RSA public key safely
// --------------------
const PUBLIC_KEY = fs.readFileSync("keys/public.pem", "utf8");

// --------------------
// Upload File (Encrypted)
// --------------------
export const uploadFile = async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({
        error: "No file uploaded or invalid file type"
      });
    }

    const { encrypted, aesKey, iv } = encryptBuffer(req.file.buffer);

    const encryptedKey = crypto.publicEncrypt(
      {
        key: PUBLIC_KEY,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING
      },
      aesKey
    ).toString("base64");

    // Prevent path traversal
    const safeFileName = Date.now() + "-" + path.basename(req.file.originalname);

    fs.writeFileSync(`${UPLOAD_DIR}/${safeFileName}`, encrypted);

    const file = await File.create({
      filename: safeFileName,
      encryptedKey,
      iv: iv.toString("base64"),
      owner: req.user.id,
      expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
      oneTime: true
    });

    res.json({ fileId: file._id });
  } catch (err) {
    console.error("UPLOAD ERROR:", err.message);
    res.status(500).json({ error: err.message || "Upload failed" });
  }
};

// --------------------
// Download File
// --------------------
export const downloadFile = async (req, res) => {
  try {
    const file = await File.findById(req.params.id);
    if (!file) return res.sendStatus(404);

    if (file.oneTime && file.downloadCount > 0) {
      return res.status(403).json({ error: "Link expired" });
    }

    const filePath = `${UPLOAD_DIR}/${file.filename}`;
    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ error: "File missing on server" });
    }

    file.downloadCount++;
    file.logs.push({ ip: req.ip, time: new Date() });
    await file.save();

    res.download(filePath);
  } catch (err) {
    console.error("DOWNLOAD ERROR:", err.message);
    res.status(500).json({ error: "Download failed" });
  }
};

// --------------------
// Get Logged-in User Files (Dashboard)
// --------------------
export const getMyFiles = async (req, res) => {
  try {
    const files = await File.find({ owner: req.user.id })
      .sort({ createdAt: -1 });

    res.json(files);
  } catch (err) {
    console.error("FETCH FILES ERROR:", err.message);
    res.status(500).json({ error: "Failed to fetch files" });
  }
};
