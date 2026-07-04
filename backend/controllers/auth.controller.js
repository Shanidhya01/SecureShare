import User from "../models/User.js";
import Device from "../models/Device.js";
import Session from "../models/Session.js";
import IOC from "../models/IOC.js";
import Passkey from "../models/Passkey.js";
import { getPolicy } from "../models/SecurityPolicy.js";
import { logSecurityEvent } from "../services/siem/siemLogger.js";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { resolveCountry } from "../utils/geoLookup.js";
import { getClientIp } from "../utils/getClientIp.js";
import { issueSessionAndToken } from "../services/iam/sessionIssuer.js";
import { scoreLogin, detectImpossibleTravel } from "../services/iam/loginRiskEngine.js";
import { checkNetworkIntel } from "../services/iam/networkIntel.js";
import {
  evaluateCountryPolicy,
  evaluateSessionLimit,
  evaluatePasswordExpiry,
  evaluateMfaRequirement,
  evaluateDevicePolicy,
  evaluatePasswordPolicy
} from "../services/iam/policyEngine.js";
import { recordLoginFailure } from "../services/iam/loginFailureTracker.js";

export const register = async (req, res) => {
  try {
    const { name, email, password, publicKey, signingPublicKey } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ error: "Name, email, and password are required" });
    }

    // Phase 9.5 (IAM): password policy is enforced at registration only - existing passwords are
    // never retroactively invalidated (see services/iam/policyEngine.js's evaluatePasswordPolicy).
    const policy = await getPolicy();
    const passwordCheck = evaluatePasswordPolicy(policy, password);
    if (!passwordCheck.valid) {
      return res.status(400).json({ error: passwordCheck.reason });
    }

    const existingUser = await User.findOne({ email: email.toLowerCase().trim() });
    if (existingUser) {
      return res.status(409).json({ error: "An account with this email already exists" });
    }

    const hashed = await bcrypt.hash(password, 10);
    const normalizedEmail = email.toLowerCase().trim();
    const newUser = await User.create({
      name: name.trim(),
      email: normalizedEmail,
      password: hashed,
      // Optional: base64 SPKI RSA-OAEP public key generated client-side for E2E encryption.
      publicKey: typeof publicKey === "string" && publicKey.length > 0 ? publicKey : undefined,
      // Optional: base64 SPKI ECDSA P-256 public signing key generated client-side (Phase 2).
      signingPublicKey: typeof signingPublicKey === "string" && signingPublicKey.length > 0 ? signingPublicKey : undefined
    });

    logSecurityEvent({
      owner: newUser._id,
      type: "register",
      message: `Account registered: ${normalizedEmail}`,
      ip: getClientIp(req),
      country: resolveCountry(req)
    }).catch((e) => console.error("Failed to record security event:", e));

    res.status(201).json({ message: "Registered" });
  } catch (err) {
    if (err?.code === 11000) {
      return res.status(409).json({ error: "An account with this email already exists" });
    }

    console.error("Register error:", err);
    res.status(500).json({ error: err?.message || "Registration failed" });
  }
};

export const login = async (req, res) => {
  try {
    const { email, password, deviceId } = req.body;
    const normalizedEmail = typeof email === "string" ? email.toLowerCase().trim() : "";

    if (!normalizedEmail || !password) {
      return res.status(400).json({ error: "Email and password are required" });
    }

    const user = await User.findOne({ email: normalizedEmail });
    if (!user) return res.status(401).json({ error: "Invalid" });

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) {
      await recordLoginFailure(user._id, req, "bad_password").catch((e) => console.error("Failed to record login failure:", e));
      return res.status(401).json({ error: "Invalid" });
    }

    const cleanDeviceId = typeof deviceId === "string" && deviceId.length > 0 ? deviceId : undefined;

    // Phase 9 (IAM): gather adaptive-auth + policy signals BEFORE any device/session is created,
    // so a device that turns out to need an MFA challenge isn't marked "seen" prematurely.
    const ip = getClientIp(req);
    const country = resolveCountry(req);

    const policy = await getPolicy();
    const countryCheck = evaluateCountryPolicy(policy, country);
    if (!countryCheck.allowed) {
      logSecurityEvent({
        owner: user._id,
        type: "policy_block",
        message: `Login blocked by country policy: ${countryCheck.reason}`,
        ip,
        country
      }).catch((e) => console.error("Failed to record security event:", e));
      return res.status(403).json({ error: countryCheck.reason });
    }

    const [existingDevice, lastSession, ipIoc, hasPasskey, networkIntel] = await Promise.all([
      cleanDeviceId ? Device.findOne({ owner: user._id, deviceId: cleanDeviceId }) : null,
      Session.findOne({ owner: user._id }).sort({ createdAt: -1 }),
      ip ? IOC.findOne({ type: "ip", value: ip, status: "active" }) : null,
      Passkey.exists({ owner: user._id }),
      checkNetworkIntel(ip)
    ]);

    const isNewDevice = !!cleanDeviceId && !existingDevice;

    // Phase 9.5: device restriction is a hard block (unlike most policies here) - see
    // policyEngine.js's evaluateDevicePolicy for why this one is safe to deny outright.
    const deviceCheck = evaluateDevicePolicy(policy, cleanDeviceId, isNewDevice);
    if (!deviceCheck.allowed) {
      logSecurityEvent({
        owner: user._id,
        type: "policy_block",
        message: `Login blocked by device policy: ${deviceCheck.reason}`,
        deviceId: cleanDeviceId,
        ip,
        country
      }).catch((e) => console.error("Failed to record security event:", e));
      return res.status(403).json({ error: deviceCheck.reason });
    }

    const deviceMfaTrusted = !!(existingDevice?.mfaTrustedUntil && existingDevice.mfaTrustedUntil > new Date());
    const impossibleTravel = detectImpossibleTravel(lastSession, country);
    const risk = scoreLogin({
      isNewDevice,
      ipIocMatch: !!ipIoc,
      countryChanged: !!(lastSession?.country && country && lastSession.country !== country),
      isVpn: networkIntel.isVpn,
      isTor: networkIntel.isTor,
      impossibleTravel
    });

    if (impossibleTravel) {
      logSecurityEvent({
        owner: user._id,
        type: "impossible_travel",
        message: `Impossible travel detected: login from ${country} within ${Math.round((Date.now() - new Date(lastSession.createdAt).getTime()) / 60000)} minute(s) of a login from ${lastSession.country}`,
        ip,
        country,
        metadata: { previousCountry: lastSession.country, previousLoginAt: lastSession.createdAt }
      }).catch((e) => console.error("Failed to record security event:", e));
    }

    const highOrCritical = risk.level === "High" || risk.level === "Critical";
    const baseMfaRequired = user.mfa.enabled && !deviceMfaTrusted;
    const stepUpForced = user.mfa.enabled && deviceMfaTrusted && (highOrCritical || user.forceMfaOnNextLogin);
    const mfaNeeded = baseMfaRequired || stepUpForced;

    if (stepUpForced) {
      logSecurityEvent({
        owner: user._id,
        type: "step_up_auth",
        message: `Step-up MFA required (${user.forceMfaOnNextLogin ? "automation-triggered" : `risk score ${risk.score}, level ${risk.level}`})`,
        ip,
        country,
        severity: risk.level === "Critical" ? "CRITICAL" : "MEDIUM",
        metadata: { reasons: risk.reasons, riskScore: risk.score, riskLevel: risk.level }
      }).catch((e) => console.error("Failed to record security event:", e));
    }

    if (mfaNeeded) {
      // Short-lived, single-purpose token - cannot be used as a real session token (no `sid`,
      // distinct `purpose` claim checked by POST /api/mfa/verify-login).
      const mfaToken = jwt.sign({ id: user._id, deviceId: cleanDeviceId, purpose: "mfa" }, process.env.JWT_SECRET, { expiresIn: "5m" });
      return res.status(202).json({ mfaRequired: true, mfaToken });
    }

    if (!user.mfa.enabled && highOrCritical) {
      logSecurityEvent({
        owner: user._id,
        type: "policy_violation",
        message: `${risk.level}-risk login without MFA enrolled (score ${risk.score}: ${risk.reasons.join(", ")})`,
        ip,
        country,
        severity: risk.level === "Critical" ? "CRITICAL" : "HIGH",
        metadata: { reasons: risk.reasons, riskScore: risk.score, riskLevel: risk.level }
      }).catch((e) => console.error("Failed to record security event:", e));
    }

    // Phase 9 policy: session limit is enforced by revoking the oldest active session rather
    // than denying the new login - see services/iam/policyEngine.js's header comment for why.
    const activeSessionCount = await Session.countDocuments({ owner: user._id, revoked: false });
    if (evaluateSessionLimit(policy, activeSessionCount).shouldRevokeOldest) {
      const oldest = await Session.findOne({ owner: user._id, revoked: false }).sort({ createdAt: 1 });
      if (oldest) {
        oldest.revoked = true;
        await oldest.save();
      }
    }

    // Phase 9.5: risk metadata rides along on the "login" SIEM event itself (see
    // sessionIssuer.js), so /api/iam/stats can chart risk-level distribution across every login,
    // not just the ones that triggered a step-up.
    const { token } = await issueSessionAndToken(user, req, {
      deviceId: cleanDeviceId,
      riskLevel: risk.level,
      riskScore: risk.score
    });

    // One-shot step-up flag (set by the SOAR "Account Lockdown Response" playbook) is cleared
    // once its requirement has been surfaced/enforced for this login.
    if (user.forceMfaOnNextLogin) {
      user.forceMfaOnNextLogin = false;
      await user.save();
    }

    const passwordExpiry = evaluatePasswordExpiry(policy, user);
    const mfaRequirement = evaluateMfaRequirement(policy, user, !!hasPasskey);

    res.json({
      token,
      user: { email: user.email, name: user.name },
      passwordExpired: passwordExpiry.expired,
      mfaSetupRequired: mfaRequirement.required,
      stepUpRecommended: !user.mfa.enabled && highOrCritical,
      riskLevel: risk.level
    });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: err?.message || "Login failed" });
  }
};
