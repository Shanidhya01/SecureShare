import express from "express";
import auth from "../middleware/auth.middleware.js";
import multer from "multer";

import {
  uploadFile,
  downloadFile,
  revokeFile,
  getMyFiles,
  getFileLogs
} from "../controllers/file.controller.js";

const upload = multer();
const router = express.Router();

router.post("/upload", auth, upload.single("file"), uploadFile);
router.get("/download/:id", downloadFile);
router.get("/my-files", auth, getMyFiles);
router.delete("/file/:id", auth, revokeFile);
router.get("/file/:id/logs", auth, getFileLogs);

export default router;
