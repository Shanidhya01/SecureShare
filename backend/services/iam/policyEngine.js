/**
 * Phase 9 (IAM): pure evaluators for the configurable SecurityPolicy (backend/models/
 * SecurityPolicy.js), consulted by auth.controller.js's login(). Deliberately pure - no DB/network
 * access - so they're directly unit-testable; the caller gathers whatever state each evaluator
 * needs (active session count, user doc, etc.) and passes it in.
 *
 * Design note: most of these are SOFT blocks (surfaced to the client as a flag, login still
 * proceeds) rather than hard denials. This app has no self-service password-reset or account-
 * unlock flow, so a hard block on, say, password expiry would permanently lock an account out
 * with no recovery path. The HARD blocks (country restriction, device restriction, session
 * timeout) are the cases where the recovery is trivial - try again from an allowed location/
 * device, or log back in - so denying outright is actually the right call there.
 */

const DAY_MS = 24 * 60 * 60 * 1000;

/** @returns {{allowed: boolean, reason?: string}} */
export function evaluateCountryPolicy(policy, country) {
  if (!policy?.allowedCountries?.length) return { allowed: true };
  if (!country) return { allowed: true }; // can't enforce what we can't resolve - fail open
  const allowed = policy.allowedCountries.includes(country);
  return allowed ? { allowed: true } : { allowed: false, reason: `Logins are not permitted from ${country}` };
}

/** @returns {{shouldRevokeOldest: boolean}} - true if the new session would exceed the limit */
export function evaluateSessionLimit(policy, activeSessionCount) {
  if (!policy?.maxSessions) return { shouldRevokeOldest: false };
  return { shouldRevokeOldest: activeSessionCount >= policy.maxSessions };
}

/** @returns {{expired: boolean}} */
export function evaluatePasswordExpiry(policy, user) {
  if (!policy?.passwordExpiryDays) return { expired: false };
  if (!user?.passwordChangedAt) return { expired: false };
  const ageMs = Date.now() - new Date(user.passwordChangedAt).getTime();
  return { expired: ageMs > policy.passwordExpiryDays * DAY_MS };
}

/** @returns {{required: boolean}} - true if the policy requires MFA and the user has none enrolled */
export function evaluateMfaRequirement(policy, user, hasPasskey = false) {
  if (!policy?.requireMFA) return { required: false };
  const hasMfa = !!user?.mfa?.enabled || hasPasskey;
  return { required: !hasMfa };
}

/**
 * Phase 9.5: device restriction - unlike the other policies above, this IS a hard block. Unlike
 * password expiry or MFA enrollment (which have no recovery flow), the recovery here is trivial:
 * log in from an already-enrolled device. `blockUntrustedDevices` denies any device this account
 * hasn't logged in from before; `allowedDeviceIds` (if non-empty) is an explicit allow-list on
 * top of that.
 * @returns {{allowed: boolean, reason?: string}}
 */
export function evaluateDevicePolicy(policy, deviceId, isNewDevice) {
  if (policy?.blockUntrustedDevices && (isNewDevice || !deviceId)) {
    return { allowed: false, reason: "Logins from new or unrecognized devices are not permitted" };
  }
  if (policy?.allowedDeviceIds?.length && !policy.allowedDeviceIds.includes(deviceId)) {
    return { allowed: false, reason: "This device is not on the allowed devices list" };
  }
  return { allowed: true };
}

/**
 * Phase 9.5: password policy, enforced only at registration (see SecurityPolicy.js's field
 * comments for why existing passwords are never retroactively invalidated).
 * @returns {{valid: boolean, reason?: string}}
 */
export function evaluatePasswordPolicy(policy, password) {
  const minLength = policy?.minPasswordLength || 6;
  if (!password || password.length < minLength) {
    return { valid: false, reason: `Password must be at least ${minLength} characters` };
  }
  if (policy?.requirePasswordComplexity) {
    const hasUpper = /[A-Z]/.test(password);
    const hasLower = /[a-z]/.test(password);
    const hasDigit = /\d/.test(password);
    const hasSymbol = /[^A-Za-z0-9]/.test(password);
    if (!(hasUpper && hasLower && hasDigit && hasSymbol)) {
      return { valid: false, reason: "Password must include uppercase, lowercase, a number, and a symbol" };
    }
  }
  return { valid: true };
}

/**
 * Phase 9.5: session timeout - consulted by backend/middleware/auth.middleware.js on every
 * authenticated request, alongside (not replacing) the existing revoked-session check.
 * @returns {{expired: boolean}}
 */
export function evaluateSessionTimeout(policy, lastActiveAt) {
  if (!policy?.sessionTimeoutMinutes) return { expired: false };
  if (!lastActiveAt) return { expired: false };
  const idleMs = Date.now() - new Date(lastActiveAt).getTime();
  return { expired: idleMs > policy.sessionTimeoutMinutes * 60 * 1000 };
}
