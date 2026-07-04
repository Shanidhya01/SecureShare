import express from "express";
import auth from "../middleware/auth.middleware.js";
import requireAdmin from "../middleware/requireAdmin.js";
import {
  listRules,
  createRule,
  updateRule,
  setRuleEnabled,
  deleteRule,
  listPlaybooks,
  createPlaybook,
  updatePlaybook,
  deletePlaybook,
  clonePlaybook,
  exportPlaybook,
  importPlaybook,
  getActionTypes,
  listExecutions,
  getExecution,
  getStats,
  exportReport
} from "../controllers/soar.controller.js";

const router = express.Router();

// Rules - viewable by any authenticated user, mutable by admins only (Phase 8 §15).
router.get("/rules", auth, listRules);
router.post("/rules", auth, requireAdmin, createRule);
router.put("/rules/:id", auth, requireAdmin, updateRule);
router.patch("/rules/:id/enabled", auth, requireAdmin, setRuleEnabled);
router.delete("/rules/:id", auth, requireAdmin, deleteRule);

// Playbooks - same viewable/admin-mutable split, plus clone/import/export.
router.get("/playbooks", auth, listPlaybooks);
router.post("/playbooks", auth, requireAdmin, createPlaybook);
router.put("/playbooks/:id", auth, requireAdmin, updatePlaybook);
router.delete("/playbooks/:id", auth, requireAdmin, deletePlaybook);
router.post("/playbooks/:id/clone", auth, requireAdmin, clonePlaybook);
router.get("/playbooks/:id/export", auth, requireAdmin, exportPlaybook);
router.post("/playbooks/import", auth, requireAdmin, importPlaybook);
router.get("/action-types", auth, getActionTypes);

// Executions/stats - any authenticated user, scoped to their own files unless admin.
router.get("/executions", auth, listExecutions);
router.get("/executions/:id", auth, getExecution);
router.get("/stats", auth, getStats);
router.get("/export", auth, exportReport);

export default router;
