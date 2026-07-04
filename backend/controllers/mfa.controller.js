import jwt from "jsonwebtoken";
import QRCode from "qrcode";
import bcrypt from "bcryptjs";
import User from "../models/User.js";
import { generateSecret, verifyToken, buildOtpauthUri } from "../services/iam/totp.js";
import { generateRecoveryCodes, consumeRecoveryCode } from "../services/iam/recoveryCodes.js";
import { issueSessionAndToken } from "../services/iam/sessionIssuer.js";
import { recordLoginFailure } from "../services/iam/loginFailureTracker.js";
import { logSecurityEvent } from "../services/siem/siemLogger.js";
import { getClientIp } from "../utils/getClientIp.js";
import { resolveCountry } from "../utils/geoLookup.js";

/* SETUP - generates a pending TOTP secret and its QR code. Not active until POST /verify
   confirms possession with a real code, so an abandoned enrollment never half-enables MFA. */
export const setup = async (req, res) => {
  const user = await User.findById(req.user.id);
  if (!user) return res.sendStatus(404);
  if (user.mfa.enabled) return res.status(400).json({ error: "MFA is already enabled" });

  const secret = generateSecret();
  user.mfa.pendingSecret = secret;
  await user.save();

  const otpauthUri = buildOtpauthUri(secret, user.email);
  const qrCodeDataUrl = await QRCode.toDataURL(otpauthUri);

  res.json({ qrCodeDataUrl, otpauthUri, secret });
};

/* VERIFY (enrollment) - confirms the pending secret with a real 6-digit code, activates MFA, and
   issues one-time recovery codes (plaintext, shown exactly once). */
export const verify = async (req, res) => {
  const { token } = req.body || {};
  const user = await User.findById(req.user.id);
  if (!user) return res.sendStatus(404);
  if (!user.mfa.pendingSecret) return res.status(400).json({ error: "No MFA enrollment in progress - call POST /setup first" });

  const ok = await verifyToken(token, user.mfa.pendingSecret);
  if (!ok) return res.status(400).json({ error: "Invalid code" });

  const { plaintextCodes, hashes } = await generateRecoveryCodes();

  user.mfa.secret = user.mfa.pendingSecret;
  user.mfa.pendingSecret = null;
  user.mfa.enabled = true;
  user.mfa.enabledAt = new Date();
  user.mfa.recoveryCodeHashes = hashes;
  await user.save();

  logSecurityEvent({
    owner: user._id,
    type: "mfa_success",
    message: "MFA enabled",
    ip: getClientIp(req),
    country: resolveCountry(req)
  }).catch((e) => console.error("Failed to record security event:", e));

  res.json({ enabled: true, recoveryCodes: plaintextCodes });
};

/* DISABLE - requires the current password to prevent a stolen/unattended session from turning
   off MFA protection. */
export const disable = async (req, res) => {
  const { password } = req.body || {};
  const user = await User.findById(req.user.id);
  if (!user) return res.sendStatus(404);

  const ok = password && (await bcrypt.compare(password, user.password));
  if (!ok) return res.status(401).json({ error: "Incorrect password" });

  user.mfa = { enabled: false, secret: null, pendingSecret: null, recoveryCodeHashes: [], enabledAt: null };
  await user.save();

  res.json({ enabled: false });
};

/* RECOVERY CODE REGENERATION - invalidates all existing codes and issues 10 fresh ones. */
export const regenerateRecoveryCodes = async (req, res) => {
  const user = await User.findById(req.user.id);
  if (!user) return res.sendStatus(404);
  if (!user.mfa.enabled) return res.status(400).json({ error: "MFA is not enabled" });

  const { plaintextCodes, hashes } = await generateRecoveryCodes();
  user.mfa.recoveryCodeHashes = hashes;
  await user.save();

  res.json({ recoveryCodes: plaintextCodes });
};

/* STATUS */
export const status = async (req, res) => {
  const user = await User.findById(req.user.id).select("mfa");
  if (!user) return res.sendStatus(404);
  res.json({ enabled: user.mfa.enabled, recoveryCodesRemaining: user.mfa.recoveryCodeHashes.length });
};

/* VERIFY-LOGIN - the second step of an MFA-gated login: exchanges the short-lived `mfaToken`
   (issued by auth.controller.js's login() when MFA is required) plus a TOTP or recovery code for
   a real session, via the same issueSessionAndToken() every login path uses. */
export const verifyLogin = async (req, res) => {
  const { mfaToken, code, trustDevice } = req.body || {};
  if (!mfaToken || !code) return res.status(400).json({ error: "mfaToken and code are required" });

  let decoded;
  try {
    decoded = jwt.verify(mfaToken, process.env.JWT_SECRET);
  } catch {
    return res.status(401).json({ error: "Invalid or expired MFA challenge" });
  }
  if (decoded.purpose !== "mfa") return res.status(401).json({ error: "Invalid MFA challenge" });

  const user = await User.findById(decoded.id);
  if (!user || !user.mfa.enabled) return res.status(401).json({ error: "Invalid MFA challenge" });

  let verified = await verifyToken(code, user.mfa.secret);
  let usedRecoveryCode = false;

  if (!verified) {
    const remaining = await consumeRecoveryCode(code, user.mfa.recoveryCodeHashes);
    if (remaining) {
      user.mfa.recoveryCodeHashes = remaining;
      verified = true;
      usedRecoveryCode = true;
    }
  }

  if (!verified) {
    await recordLoginFailure(user._id, req, "bad_mfa_code").catch((e) => console.error("Failed to record login failure:", e));
    logSecurityEvent({
      owner: user._id,
      type: "mfa_failed",
      message: "MFA verification failed",
      ip: getClientIp(req),
      country: resolveCountry(req)
    }).catch((e) => console.error("Failed to record security event:", e));
    return res.status(401).json({ error: "Invalid code" });
  }

  if (user.forceMfaOnNextLogin) user.forceMfaOnNextLogin = false;
  await user.save();

  const { token } = await issueSessionAndToken(user, req, {
    deviceId: decoded.deviceId,
    mfaVerified: true,
    trustDeviceForMfa: !!trustDevice
  });

  res.json({ token, user: { email: user.email, name: user.name }, usedRecoveryCode });
};
