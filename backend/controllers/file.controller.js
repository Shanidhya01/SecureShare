import fs from "fs";
import crypto from "crypto";
import multer from "multer";
import File from "../models/File.js";
import { encryptBuffer } from "../utils/encrypt.js";

const upload = multer();
export const uploadMiddleware = upload.single("file");


const PUBLIC_KEY = fs.readFileSync("keys/public.pem", "utf8");

export const uploadFile = async (req, res) => {
  try {
    const { encrypted, aesKey, iv } = encryptBuffer(req.file.buffer);

    const encryptedKey = crypto.publicEncrypt(
      {
        key: PUBLIC_KEY,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING
      },
      aesKey
    ).toString("base64");

    fs.writeFileSync(`uploads/${req.file.originalname}`, encrypted);

    const file = await File.create({
      filename: req.file.originalname,
      encryptedKey,
      iv: iv.toString("base64"),
      owner: req.user.id,
      expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
      oneTime: true
    });

    res.json({ fileId: file._id });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Encryption failed" });
  }
};

// ✅ EXPORT downloadFile  (THIS WAS MISSING)
export const downloadFile = async (req, res) => {
  try {
    const file = await File.findById(req.params.id);
    if (!file) return res.sendStatus(404);

    if (file.oneTime && file.downloadCount > 0) {
      return res.status(403).json({ error: "Link expired" });
    }

    file.downloadCount++;
    file.logs.push({ ip: req.ip, time: new Date() });
    await file.save();

    res.download(`uploads/${file.filename}`);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Download failed" });
  }
};
