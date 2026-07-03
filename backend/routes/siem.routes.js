import express from "express";
import auth from "../middleware/auth.middleware.js";
import {
  getDashboard,
  getEvents,
  getIncidents,
  getIncidentById,
  search,
  exportEvents,
  getStats,
  reportSignatureEvent,
  getCatalog
} from "../controllers/siem.controller.js";

const router = express.Router();

router.get("/dashboard", auth, getDashboard);
router.get("/events", auth, getEvents);
router.get("/incidents", auth, getIncidents);
router.get("/incidents/:id", auth, getIncidentById);
router.get("/search", auth, search);
router.get("/export", auth, exportEvents);
router.get("/stats", auth, getStats);
router.get("/catalog", auth, getCatalog);
router.post("/events/signature", auth, reportSignatureEvent);

export default router;
