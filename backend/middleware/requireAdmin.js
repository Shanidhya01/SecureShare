import User from "../models/User.js";

/**
 * Phase 8 (SOAR): gates automation rule/playbook management to admin accounts. Must run after
 * the default `auth` middleware (backend/middleware/auth.middleware.js), which sets `req.user`.
 * Always re-checks the User document itself rather than trusting the JWT's `isAdmin` claim,
 * since a user's admin status could change after a token was issued.
 */
export default async function requireAdmin(req, res, next) {
  const user = await User.findById(req.user.id).select("isAdmin");
  if (!user?.isAdmin) {
    return res.status(403).json({ error: "Admin access required" });
  }
  next();
}
