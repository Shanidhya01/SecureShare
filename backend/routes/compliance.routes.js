import express from "express";
import auth from "../middleware/auth.middleware.js";
import requireAdmin from "../middleware/requireAdmin.js";
import {
  listFrameworks,
  getFramework,
  updateFramework,
  listControls,
  getControl,
  listAssessments,
  getFindings,
  runScan,
  listEvidence,
  approveEvidence,
  listPolicies,
  updatePolicy,
  createPolicy,
  patchPolicyById,
  getPolicyHistoryEndpoint,
  rollbackPolicyEndpoint,
  listReports,
  generateReport,
  getDashboard
} from "../controllers/compliance.controller.js";

const router = express.Router();

// Phase 10 (Compliance & Governance): an org-wide governance area, admin-only end to end -
// matches SOAR's rule/playbook config gating rather than a per-user page like /identity.
router.use(auth, requireAdmin);

router.get("/dashboard", getDashboard);

router.get("/frameworks", listFrameworks);
router.get("/frameworks/:id", getFramework);
router.get("/framework/:id", getFramework); // singular alias
router.patch("/frameworks/:id", updateFramework);

router.get("/controls", listControls);
router.get("/control/:id", getControl); // singular alias

router.get("/assessments", listAssessments);
router.get("/findings", getFindings);
router.post("/scan", runScan);
router.post("/run", runScan); // alias

router.get("/evidence", listEvidence);
router.post("/evidence/:id/approve", approveEvidence);

router.get("/policies", listPolicies);
router.post("/policies", createPolicy);
router.put("/policies/:name", updatePolicy);
router.patch("/policies/:id", patchPolicyById);
router.get("/policies/:name/history", getPolicyHistoryEndpoint);
router.post("/policies/:name/rollback/:version", rollbackPolicyEndpoint);

router.get("/reports", listReports);
router.post("/reports", generateReport);
router.post("/report", generateReport); // alias
router.get("/reports/export", generateReport);

// Dedicated export-by-format routes, alongside the existing ?format= query-param style above.
router.get("/export/pdf", (req, res, next) => { req.query.format = "pdf"; next(); }, generateReport);
router.get("/export/csv", (req, res, next) => { req.query.format = "csv"; next(); }, generateReport);
router.get("/export/json", (req, res, next) => { req.query.format = "json"; next(); }, generateReport);

export default router;
