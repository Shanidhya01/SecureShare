import express from "express";
import auth from "../middleware/auth.middleware.js";
import { getMySecurityEvents } from "../controllers/security.controller.js";

const router = express.Router();

router.get("/events", auth, getMySecurityEvents);

export default router;
