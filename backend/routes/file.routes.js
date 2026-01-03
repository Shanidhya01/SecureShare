import express from "express";
import auth from "../middleware/auth.middleware.js";
import {
  uploadFile,
  downloadFile,
  uploadMiddleware
} from "../controllers/file.controller.js";

const router = express.Router();

router.post("/upload", auth, uploadMiddleware, uploadFile);
router.get("/download/:id", downloadFile);

export default router;
