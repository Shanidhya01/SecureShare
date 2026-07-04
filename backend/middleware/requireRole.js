import User from "../models/User.js";

/**
 * Phase 9 (IAM/RBAC): finer-grained role gate than requireAdmin.js's admin-or-not check. Applied
 * only to new Phase 9 endpoints (e.g. PATCH /api/iam/users/:id/role requires "org_owner") - never
 * retrofitted onto prior phases' routes, so no existing endpoint's access rules change.
 * Must run after the default `auth` middleware.
 */
export default function requireRole(...allowedRoles) {
  return async (req, res, next) => {
    const user = await User.findById(req.user.id).select("role");
    if (!allowedRoles.includes(user?.role)) {
      return res.status(403).json({ error: `Requires role: ${allowedRoles.join(" or ")}` });
    }
    next();
  };
}
