/**
 * Phase 9 (IAM/SOAR integration): records a failed login attempt as a `login_failed` SecurityEvent
 * carrying a rolling 15-minute failure count in its metadata. This is what finally gives Phase 8's
 * dormant `MULTIPLE_FAILED_LOGINS` trigger a real source - see
 * backend/services/soar/ruleMatcher.js's eventTriggerFor(), which reads `metadata.recentFailureCount`.
 * Shared by both a bad password (auth.controller.js) and a bad MFA code (mfa.controller.js) so
 * either failure mode counts toward the same lockdown automation.
 */
import SecurityEvent from "../../models/SecurityEvent.js";
import { logSecurityEvent } from "../siem/siemLogger.js";
import { getClientIp } from "../../utils/getClientIp.js";
import { resolveCountry } from "../../utils/geoLookup.js";

const WINDOW_MS = 15 * 60 * 1000;

/** @returns {Promise<number>} the failure count including this one */
export async function recordLoginFailure(userId, req, reason) {
  const since = new Date(Date.now() - WINDOW_MS);
  const recentCount = await SecurityEvent.countDocuments({
    owner: userId,
    type: "login_failed",
    createdAt: { $gte: since }
  });
  const recentFailureCount = recentCount + 1;

  await logSecurityEvent({
    owner: userId,
    type: "login_failed",
    message: `Failed login attempt (${reason})`,
    ip: getClientIp(req),
    country: resolveCountry(req),
    metadata: { reason, recentFailureCount }
  });

  return recentFailureCount;
}
