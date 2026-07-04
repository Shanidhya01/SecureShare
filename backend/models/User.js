import mongoose from "mongoose";

const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String,

  // base64 SPKI DER, RSA-OAEP-SHA256 public key generated client-side for zero-knowledge E2E encryption.
  // The matching private key never leaves the browser (see frontend/lib/crypto/keyStorage.ts).
  publicKey: String,

  // base64 SPKI DER, ECDSA P-256 public signing key generated client-side (Phase 2: integrity/
  // authenticity verification). The matching private signing key never leaves the browser either.
  signingPublicKey: String,

  // Phase 8 (SOAR): the first admin concept in this codebase. Defaults to false for every
  // existing/new account - grant manually (e.g. directly in Mongo) to allow managing automation
  // rules/playbooks. Never settable via any public API.
  isAdmin: { type: Boolean, default: false },

  // Phase 9 (IAM/RBAC): a fuller role model layered on top of isAdmin rather than replacing it -
  // backend/middleware/requireAdmin.js accepts either. Never settable via any public API except
  // PATCH /api/iam/users/:id/role, which itself requires role "org_owner".
  role: {
    type: String,
    enum: ["user", "moderator", "security_analyst", "administrator", "org_owner"],
    default: "user"
  },

  // Phase 9: TOTP multi-factor authentication. `pendingSecret` holds a freshly-generated secret
  // during enrollment before the user confirms possession with a real code (POST /api/mfa/verify);
  // it's promoted to `secret` only on success, so an abandoned enrollment never half-enables MFA.
  mfa: {
    enabled: { type: Boolean, default: false },
    secret: { type: String, default: null },
    pendingSecret: { type: String, default: null },
    recoveryCodeHashes: { type: [String], default: [] },
    enabledAt: { type: Date, default: null }
  },

  // Phase 9: password expiry policy support (services/iam/policyEngine.js). Defaults to account
  // creation time so existing accounts get a sensible baseline instead of an undefined age.
  passwordChangedAt: { type: Date, default: Date.now },

  // Phase 9 (SOAR integration): set by the "Account Lockdown Response" playbook's
  // requireMfaStepUp action after repeated failed logins; consulted once by the next login
  // attempt and then cleared, exactly like a one-shot step-up challenge.
  forceMfaOnNextLogin: { type: Boolean, default: false }
});

export default mongoose.model("User", userSchema);
