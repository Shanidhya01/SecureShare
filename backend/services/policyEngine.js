/**
 * Zero Trust download policy engine.
 *
 * Pure function - no DB or network access - so it's cheap to unit test and safe to reuse from
 * any call site (currently just downloadFile in file.controller.js, but designed to be reusable
 * wherever a "should this request be allowed to reach this file's bytes" decision is needed).
 *
 * Every check is independently opt-in via the file's `policy` subdocument (see models/File.js).
 * A file with no policy configured (all fields empty/default) always evaluates to "allow" -
 * this is what preserves compatibility with every file that existed before Phase 3.
 */

/** True if any policy restriction is actually configured (non-empty/non-default). */
export function hasActivePolicy(policy) {
  if (!policy) return false;
  return !!(
    (policy.allowedCountries && policy.allowedCountries.length > 0) ||
    (policy.allowedIPs && policy.allowedIPs.length > 0) ||
    (policy.allowedDevices && policy.allowedDevices.length > 0) ||
    (policy.businessHours && policy.businessHours.enabled) ||
    (policy.maxDevices && policy.maxDevices > 0) ||
    policy.requireApproval
  );
}

/**
 * @param {object} policy - a File.policy subdocument (may be undefined/empty)
 * @param {object} context
 * @param {string|null} context.ip - resolved client IP
 * @param {string|null} context.country - resolved country code, "Unknown" if unresolvable
 * @param {string|null} context.deviceId - client-supplied device fingerprint hash, if any
 * @param {Date} context.time - request time (business-hours check uses UTC hour)
 * @param {string[]} context.knownDeviceIds - distinct device IDs that have already downloaded
 *   this file (used by the maxDevices check); caller computes this from file.logs
 * @param {string|null} context.userId - authenticated user id, if the requester is logged in
 * @param {boolean} context.deviceTrusted - whether context.deviceId is a trusted device for
 *   context.userId (only meaningful when userId is set)
 * @returns {{decision: "allow"} | {decision: "deny", reason: string}}
 */
export function evaluateDownloadPolicy(policy, context) {
  if (!hasActivePolicy(policy)) {
    return { decision: "allow" };
  }

  if (policy.allowedCountries.length > 0) {
    if (!context.country || !policy.allowedCountries.includes(context.country)) {
      return { decision: "deny", reason: `Country not permitted (${context.country || "unknown"})` };
    }
  }

  if (policy.allowedIPs.length > 0) {
    if (!context.ip || !policy.allowedIPs.includes(context.ip)) {
      return { decision: "deny", reason: "IP address not permitted" };
    }
  }

  if (policy.businessHours?.enabled) {
    const hour = context.time.getUTCHours();
    const { startHour, endHour } = policy.businessHours;
    const withinRange =
      startHour <= endHour ? hour >= startHour && hour < endHour : hour >= startHour || hour < endHour; // overnight window support, e.g. 22-6
    if (!withinRange) {
      return { decision: "deny", reason: `Outside allowed access hours (${startHour}:00-${endHour}:00 UTC)` };
    }
  }

  if (policy.allowedDevices.length > 0) {
    if (!context.deviceId || !policy.allowedDevices.includes(context.deviceId)) {
      return { decision: "deny", reason: "Device not authorized for this file" };
    }
  }

  if (policy.maxDevices && policy.maxDevices > 0) {
    const known = context.knownDeviceIds || [];
    const isKnownDevice = !!context.deviceId && known.includes(context.deviceId);
    if (!isKnownDevice && known.length >= policy.maxDevices) {
      return { decision: "deny", reason: `Maximum number of devices (${policy.maxDevices}) already used for this file` };
    }
  }

  if (policy.requireApproval) {
    if (!context.userId) {
      return { decision: "deny", reason: "This file requires an authenticated recipient" };
    }
    if (!context.deviceTrusted) {
      return { decision: "deny", reason: "This file requires a trusted device" };
    }
  }

  return { decision: "allow" };
}
