import User from "../models/User.js";

const ADMIN_ROLES = ["administrator", "org_owner"];

/**
 * Phase 8 (SOAR): gates automation rule/playbook management to admin accounts. Must run after
 * the default `auth` middleware (backend/middleware/auth.middleware.js), which sets `req.user`.
 * Always re-checks the User document itself rather than trusting the JWT's `isAdmin`/`role`
 * claims, since a user's admin status could change after a token was issued.
 *
 * Phase 9 (IAM/RBAC) extended this to also accept the newer `role` field (`administrator` or
 * `org_owner`), on top of the original `isAdmin` boolean - additive, so every existing Phase 8
 * admin account (granted via `isAdmin`) keeps working unchanged.
 */
export default async function requireAdmin(req, res, next) {
  const user = await User.findById(req.user.id).select("isAdmin role");
  if (!user?.isAdmin && !ADMIN_ROLES.includes(user?.role)) {
    return res.status(403).json({ error: "Admin access required" });
  }
  next();
}
