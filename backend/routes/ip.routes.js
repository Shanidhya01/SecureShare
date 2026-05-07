import express from "express";
import { getClientIp } from "../utils/getClientIp.js";

const router = express.Router();

/**
 * Endpoint to detect the client's IP address
 * Used by frontend to get the real IP before downloading
 */
router.get("/detect-ip", (req, res) => {
  const clientIp = getClientIp(req);
  res.json({ ip: clientIp });
});

export default router;
