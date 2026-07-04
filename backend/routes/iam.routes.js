import express from "express";
import auth from "../middleware/auth.middleware.js";
import requireAdmin from "../middleware/requireAdmin.js";
import requireRole from "../middleware/requireRole.js";
import {
  getSecurityPolicy,
  updateSecurityPolicy,
  listUsers,
  updateUserRole,
  getRoles,
  getLoginHistory,
  getIdentityStats
} from "../controllers/iam.controller.js";

const router = express.Router();

// Policy - readable by any authenticated user (so the frontend can explain login behavior),
// mutable only by an admin.
router.get("/policy", auth, getSecurityPolicy);
router.put("/policy", auth, requireAdmin, updateSecurityPolicy);

// Roles - listing/viewing requires admin; granting a role is reserved for org_owner, since it can
// itself grant admin power.
router.get("/roles", auth, requireAdmin, getRoles);
router.get("/users", auth, requireAdmin, listUsers);
router.patch("/users/:id/role", auth, requireRole("org_owner"), updateUserRole);

router.get("/login-history", auth, getLoginHistory);
router.get("/stats", auth, getIdentityStats);

export default router;
