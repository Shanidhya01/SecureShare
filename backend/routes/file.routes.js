import express from "express";
import auth from "../middleware/auth.middleware.js";
import multer from "multer";

import {
  uploadFile,
  downloadFile,
  revokeFile,
  getMyFiles,
  getAllFiles,
  getFileLogs,
  getFileMeta,
  deleteFile
} from "../controllers/file.controller.js";

const upload = multer();
const router = express.Router();

router.post("/upload", auth, upload.single("file"), uploadFile);
router.get("/download/:id", downloadFile);
router.get("/my-files", auth, getMyFiles);
router.get("/all-files", auth, getAllFiles);
router.delete("/file/:id", auth, revokeFile);
router.delete("/file/:id/permanent", auth, deleteFile);
router.get("/file/:id/logs", auth, getFileLogs);
router.get("/file/:id/meta", getFileMeta);

export default router;
