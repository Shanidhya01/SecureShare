import express from "express";
import auth from "../middleware/auth.middleware.js";
import requireAdmin from "../middleware/requireAdmin.js";
import {
  getDashboard,
  listRepositories,
  createOrRescanRepository,
  listDependencyFindings,
  listSecretFindings,
  listSastFindings,
  listContainerFindings,
  listIacFindings,
  runContainerScanEndpoint,
  listSboms,
  generateSbomEndpoint,
  listReports,
  runScan,
  exportReport
} from "../controllers/devsecops.controller.js";

const router = express.Router();

// Phase 12 (DevSecOps/Supply Chain): an org-wide engineering-security concern, admin-only end to
// end - same gating pattern as Compliance/SOAR/Cloud Security.
router.use(auth, requireAdmin);

router.get("/dashboard", getDashboard);

router.get("/repositories", listRepositories);
router.post("/repositories", createOrRescanRepository);

router.get("/dependencies", listDependencyFindings);
router.get("/secrets", listSecretFindings);
router.get("/sast", listSastFindings);
router.get("/container", listContainerFindings);
router.post("/container", runContainerScanEndpoint);
router.get("/iac", listIacFindings);

router.get("/sbom", listSboms);
router.post("/sbom", generateSbomEndpoint);

router.get("/reports", listReports);

router.post("/scan", runScan);

router.get("/export/pdf", (req, res, next) => { req.params.format = "pdf"; next(); }, exportReport);
router.get("/export/csv", (req, res, next) => { req.params.format = "csv"; next(); }, exportReport);
router.get("/export/json", (req, res, next) => { req.params.format = "json"; next(); }, exportReport);

export default router;
