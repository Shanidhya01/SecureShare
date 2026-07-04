import mongoose from "mongoose";

/**
 * Phase 9 (IAM): a single, global configurable security policy document (no multi-tenant/org
 * concept exists in this codebase, so "singleton" rather than per-organization). Consulted by
 * backend/services/iam/policyEngine.js's pure evaluator functions at login. See policyEngine.js
 * for why most of these are soft-blocks (surfaced to the client) rather than hard denials.
 */
const securityPolicySchema = new mongoose.Schema(
  {
    singleton: { type: String, default: "global", unique: true },

    requireMFA: { type: Boolean, default: false },
    passwordExpiryDays: { type: Number, default: 0 }, // 0 = disabled
    sessionTimeoutMinutes: { type: Number, default: 0 }, // 0 = disabled
    maxSessions: { type: Number, default: 0 }, // 0 = unlimited
    allowedCountries: { type: [String], default: [] }, // empty = unrestricted
    blockUntrustedDevices: { type: Boolean, default: false },

    // Phase 9.5: device restrictions - if non-empty, only these client-generated device
    // fingerprint hashes (see frontend/lib/security/fingerprint.ts) may log in at all.
    allowedDeviceIds: { type: [String], default: [] }, // empty = unrestricted

    // Phase 9.5: password policy, enforced at registration only (existing accounts/passwords are
    // never invalidated retroactively - there is no forced-reset flow in this app).
    minPasswordLength: { type: Number, default: 6 },
    requirePasswordComplexity: { type: Boolean, default: false } // upper+lower+digit+symbol
  },
  { timestamps: true }
);

// Phase 9.5: getPolicy() is now called on nearly every authenticated request (auth.middleware.js
// enforces session timeout), so a short in-memory cache avoids a DB round-trip per request while
// keeping policy changes visible within a few seconds - no external cache dependency needed for
// a single small singleton document.
let cachedPolicy = null;
let cachedAt = 0;
const CACHE_TTL_MS = 15000;

export async function getPolicy() {
  if (cachedPolicy && Date.now() - cachedAt < CACHE_TTL_MS) return cachedPolicy;

  const policy =
    (await mongoose.models.SecurityPolicy.findOne({ singleton: "global" })) ||
    (await mongoose.models.SecurityPolicy.create({ singleton: "global" }));

  cachedPolicy = policy;
  cachedAt = Date.now();
  return policy;
}

/** Invalidates the cache immediately after an admin updates the policy, so the new settings take
 *  effect on the very next request rather than waiting out the TTL. */
export function invalidatePolicyCache() {
  cachedPolicy = null;
}

export default mongoose.model("SecurityPolicy", securityPolicySchema);
