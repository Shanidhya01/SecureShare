import express from "express";
import auth from "../middleware/auth.middleware.js";
import { getMySessions, revokeSession } from "../controllers/session.controller.js";

const router = express.Router();

router.get("/", auth, getMySessions);
router.delete("/:sessionId", auth, revokeSession);

export default router;
