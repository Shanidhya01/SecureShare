import User from "../models/User.js";
import Device from "../models/Device.js";
import SecurityEvent from "../models/SecurityEvent.js";
import SecurityPolicy, { getPolicy, invalidatePolicyCache } from "../models/SecurityPolicy.js";

const ROLES = ["user", "moderator", "security_analyst", "administrator", "org_owner"];

/* ============================== POLICY ============================== */

export const getSecurityPolicy = async (_req, res) => {
  const policy = await getPolicy();
  res.json(policy);
};

export const updateSecurityPolicy = async (req, res) => {
  const {
    requireMFA, passwordExpiryDays, sessionTimeoutMinutes, maxSessions, allowedCountries, blockUntrustedDevices,
    allowedDeviceIds, minPasswordLength, requirePasswordComplexity
  } = req.body || {};

  const update = {};
  if (typeof requireMFA === "boolean") update.requireMFA = requireMFA;
  if (typeof passwordExpiryDays === "number") update.passwordExpiryDays = passwordExpiryDays;
  if (typeof sessionTimeoutMinutes === "number") update.sessionTimeoutMinutes = sessionTimeoutMinutes;
  if (typeof maxSessions === "number") update.maxSessions = maxSessions;
  if (Array.isArray(allowedCountries)) update.allowedCountries = allowedCountries;
  if (typeof blockUntrustedDevices === "boolean") update.blockUntrustedDevices = blockUntrustedDevices;
  if (Array.isArray(allowedDeviceIds)) update.allowedDeviceIds = allowedDeviceIds;
  if (typeof minPasswordLength === "number") update.minPasswordLength = minPasswordLength;
  if (typeof requirePasswordComplexity === "boolean") update.requirePasswordComplexity = requirePasswordComplexity;

  const policy = await SecurityPolicy.findOneAndUpdate({ singleton: "global" }, update, { new: true, upsert: true });
  invalidatePolicyCache();
  res.json(policy);
};

/* ============================== ROLES ============================== */

export const listUsers = async (_req, res) => {
  const users = await User.find().select("name email role isAdmin createdAt");
  res.json(users);
};

export const updateUserRole = async (req, res) => {
  const { role } = req.body || {};
  if (!ROLES.includes(role)) return res.status(400).json({ error: `role must be one of: ${ROLES.join(", ")}` });

  const user = await User.findByIdAndUpdate(req.params.id, { role }, { new: true }).select("name email role");
  if (!user) return res.sendStatus(404);

  res.json(user);
};

export const getRoles = async (_req, res) => {
  res.json(ROLES);
};

/* ============================ LOGIN HISTORY ============================ */

export const getLoginHistory = async (req, res) => {
  const events = await SecurityEvent.find({
    owner: req.user.id,
    type: {
      $in: [
        "login", "login_failed", "mfa_success", "mfa_failed", "passkey_login",
        "step_up_auth", "policy_block", "device_trusted", "impossible_travel"
      ]
    }
  })
    .sort({ createdAt: -1 })
    .limit(100);

  res.json(events);
};

/* ============================== ANALYTICS (Phase 9.5) ============================== */

/* Charts on /identity: Risk Levels, MFA Usage, Countries, Devices, Failed Logins. Scoped to the
   caller's own account - there is no cross-account analytics view in this app. */
export const getIdentityStats = async (req, res) => {
  const owner = req.user.id;
  const since90d = new Date(Date.now() - 90 * 24 * 60 * 60 * 1000);

  const [logins, failedLogins, mfaEvents, devices] = await Promise.all([
    SecurityEvent.find({ owner, type: "login", createdAt: { $gte: since90d } }).select("metadata country deviceId createdAt"),
    SecurityEvent.find({ owner, type: "login_failed", createdAt: { $gte: since90d } }).select("createdAt"),
    SecurityEvent.find({ owner, type: { $in: ["mfa_success", "passkey_login"] }, createdAt: { $gte: since90d } }).select("type"),
    Device.find({ owner, revoked: false }).select("deviceId label lastSeenAt")
  ]);

  const byRiskLevel = { Low: 0, Medium: 0, High: 0, Critical: 0 };
  const byCountry = {};
  const byDevice = {};
  let mfaLogins = 0;

  for (const e of logins) {
    const level = e.metadata?.riskLevel || "Low";
    if (byRiskLevel[level] !== undefined) byRiskLevel[level]++;
    if (e.country) byCountry[e.country] = (byCountry[e.country] || 0) + 1;
    if (e.deviceId) byDevice[e.deviceId] = (byDevice[e.deviceId] || 0) + 1;
    if (e.metadata?.authMethod && e.metadata.authMethod !== "password") mfaLogins++;
  }

  const failedLoginsByDay = {};
  for (const e of failedLogins) {
    const day = e.createdAt.toISOString().slice(0, 10);
    failedLoginsByDay[day] = (failedLoginsByDay[day] || 0) + 1;
  }

  res.json({
    totalLogins: logins.length,
    byRiskLevel,
    mfaUsage: { withMfaOrPasskey: mfaLogins, passwordOnly: logins.length - mfaLogins },
    mfaEventCount: mfaEvents.length,
    byCountry,
    byDevice: Object.fromEntries(
      Object.entries(byDevice).map(([deviceId, count]) => [
        devices.find((d) => d.deviceId === deviceId)?.label || deviceId,
        count
      ])
    ),
    failedLoginsTotal: failedLogins.length,
    failedLoginsByDay
  });
};
