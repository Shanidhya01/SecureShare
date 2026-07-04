/**
 * Phase 9 (IAM) adaptive authentication, extended in Phase 9.5 with a fourth (CRITICAL) tier and
 * three new signals (VPN, TOR, impossible travel) - still a pure, dependency-free classifier
 * mirroring backend/services/riskEngine.js's style, scoring a login attempt instead of an
 * uploaded file.
 *
 * Signals are gathered by the caller (backend/controllers/auth.controller.js) BEFORE calling
 * this - isNewDevice from the existing device-lookup logic, ipIocMatch from a local-only (no
 * external network call) Phase 7 IOC lookup, countryChanged/impossibleTravel from comparing
 * against the user's most recent prior Session, isVpn/isTor from
 * services/iam/networkIntel.js's heuristic checks.
 */
const WEIGHTS = {
  isNewDevice: 20,
  ipIocMatch: 40,
  countryChanged: 15,
  isVpn: 20,
  isTor: 35,
  impossibleTravel: 40
};

// Below this many minutes between two logins from different countries, the travel is physically
// implausible (no commercial flight is that fast) - a simplification given this codebase has no
// lat/long geo-database, only country-level resolution (see backend/utils/geoLookup.js).
export const IMPOSSIBLE_TRAVEL_WINDOW_MINUTES = 120;

/**
 * @param {{isNewDevice?: boolean, ipIocMatch?: boolean, countryChanged?: boolean, isVpn?: boolean, isTor?: boolean, impossibleTravel?: boolean}} signals
 * @returns {{score: number, level: "Low"|"Medium"|"High"|"Critical", reasons: string[]}}
 */
export function scoreLogin(signals = {}) {
  let score = 0;
  const reasons = [];

  if (signals.isNewDevice) {
    score += WEIGHTS.isNewDevice;
    reasons.push("Login from a new/unrecognized device");
  }
  if (signals.ipIocMatch) {
    score += WEIGHTS.ipIocMatch;
    reasons.push("Login IP matches a known malicious indicator");
  }
  if (signals.countryChanged) {
    score += WEIGHTS.countryChanged;
    reasons.push("Login country differs from the account's most recent session");
  }
  if (signals.isVpn) {
    score += WEIGHTS.isVpn;
    reasons.push("Login IP appears to be a VPN/proxy exit node");
  }
  if (signals.isTor) {
    score += WEIGHTS.isTor;
    reasons.push("Login IP appears to be a Tor exit node");
  }
  if (signals.impossibleTravel) {
    score += WEIGHTS.impossibleTravel;
    reasons.push(`Impossible travel: country changed within ${IMPOSSIBLE_TRAVEL_WINDOW_MINUTES} minutes of the previous login`);
  }

  score = Math.min(100, score);
  const level = score >= 80 ? "Critical" : score >= 55 ? "High" : score >= 25 ? "Medium" : "Low";

  return { score, level, reasons };
}

/**
 * Pure impossible-travel check: true if the account's country changed since its most recent
 * session AND that session started less than IMPOSSIBLE_TRAVEL_WINDOW_MINUTES ago. Country-level
 * only (no distance/speed calculation) - documented simplification, not a geodesic model.
 * @param {{country?: string, createdAt?: Date|string}|null} lastSession
 * @param {string|null} currentCountry
 * @param {Date} [now]
 */
export function detectImpossibleTravel(lastSession, currentCountry, now = new Date()) {
  if (!lastSession?.country || !currentCountry) return false;
  if (lastSession.country === currentCountry) return false;

  const lastLoginAt = new Date(lastSession.createdAt);
  const minutesSince = (now.getTime() - lastLoginAt.getTime()) / 60000;
  return minutesSince >= 0 && minutesSince < IMPOSSIBLE_TRAVEL_WINDOW_MINUTES;
}
