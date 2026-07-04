/**
 * Phase 9 (IAM): the single place that finalizes a login - device bookkeeping, Session creation,
 * SIEM logging, and JWT signing. Extracted verbatim from backend/controllers/auth.controller.js's
 * original login() (which used to do all of this inline) so that plain password login, MFA-
 * verified login, and passkey login all produce identical sessions/tokens/events instead of each
 * reimplementing this tail slightly differently.
 */
import crypto from "crypto";
import jwt from "jsonwebtoken";
import Device from "../../models/Device.js";
import Session from "../../models/Session.js";
import { logSecurityEvent } from "../siem/siemLogger.js";
import { parseUserAgent } from "../../utils/deviceContext.js";
import { resolveCountry } from "../../utils/geoLookup.js";
import { getClientIp } from "../../utils/getClientIp.js";

/**
 * @param {import("mongoose").Document} user
 * @param {import("express").Request} req
 * @param {{deviceId?: string, mfaVerified?: boolean, passkeyVerified?: boolean, trustDeviceForMfa?: boolean, riskLevel?: string, riskScore?: number}} [options]
 * @returns {Promise<{token: string, sessionId: string, ip: string, country: string|null, deviceId: string|undefined}>}
 */
export async function issueSessionAndToken(user, req, options = {}) {
  const { deviceId, mfaVerified, passkeyVerified, trustDeviceForMfa, riskLevel, riskScore } = options;

  const ip = getClientIp(req);
  const country = resolveCountry(req);
  const { browser, operatingSystem } = parseUserAgent(req.headers["user-agent"]);
  const cleanDeviceId = typeof deviceId === "string" && deviceId.length > 0 ? deviceId : undefined;

  if (cleanDeviceId) {
    const existingDevice = await Device.findOne({ owner: user._id, deviceId: cleanDeviceId });
    if (existingDevice) {
      existingDevice.lastSeenAt = new Date();
      existingDevice.lastIp = ip;
      if (trustDeviceForMfa) {
        existingDevice.mfaTrustedUntil = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
      }
      await existingDevice.save();
    } else {
      await Device.create({
        owner: user._id,
        deviceId: cleanDeviceId,
        label: `${browser} on ${operatingSystem}`,
        browser,
        operatingSystem,
        userAgent: req.headers["user-agent"] || "",
        lastIp: ip,
        trusted: true,
        mfaTrustedUntil: trustDeviceForMfa ? new Date(Date.now() + 30 * 24 * 60 * 60 * 1000) : null
      });
      await logSecurityEvent({
        owner: user._id,
        type: "new_device",
        message: `New device signed in: ${browser} on ${operatingSystem}`,
        deviceId: cleanDeviceId,
        ip,
        country
      });
    }

    if (trustDeviceForMfa) {
      logSecurityEvent({
        owner: user._id,
        type: "device_trusted",
        message: `Device trusted for MFA: ${browser} on ${operatingSystem}`,
        deviceId: cleanDeviceId,
        ip,
        country
      }).catch((e) => console.error("Failed to record security event:", e));
    }
  }

  const sessionId = crypto.randomUUID();
  await Session.create({
    owner: user._id,
    sessionId,
    deviceId: cleanDeviceId,
    browser,
    operatingSystem,
    ip,
    country
  });

  // Phase 9.5: riskLevel/riskScore/the auth method used ride along on the canonical login event
  // itself so /api/iam/stats can chart risk-level distribution and MFA/passkey usage across every
  // login, not just the ones that happened to trigger a step-up or a dedicated mfa_success event.
  logSecurityEvent({
    owner: user._id,
    type: "login",
    message: `Signed in from ${browser} on ${operatingSystem}`,
    deviceId: cleanDeviceId,
    ip,
    country,
    metadata: {
      riskLevel: riskLevel || "Low",
      riskScore: riskScore ?? 0,
      authMethod: passkeyVerified ? "passkey" : mfaVerified ? "password+mfa" : "password"
    }
  }).catch((e) => console.error("Failed to record security event:", e));
  logSecurityEvent({
    owner: user._id,
    type: "session_created",
    message: `New session started on ${browser} on ${operatingSystem}`,
    deviceId: cleanDeviceId,
    ip,
    country
  }).catch((e) => console.error("Failed to record security event:", e));

  if (mfaVerified) {
    logSecurityEvent({
      owner: user._id,
      type: "mfa_success",
      message: "MFA verification succeeded",
      deviceId: cleanDeviceId,
      ip,
      country
    }).catch((e) => console.error("Failed to record security event:", e));
  }
  if (passkeyVerified) {
    logSecurityEvent({
      owner: user._id,
      type: "passkey_login",
      message: "Signed in with a passkey",
      deviceId: cleanDeviceId,
      ip,
      country
    }).catch((e) => console.error("Failed to record security event:", e));
  }

  // Phase 8: isAdmin kept for backward compatibility with existing SOAR admin gating; Phase 9
  // adds `role` alongside it (both are UI convenience claims only - every admin-gated backend
  // route re-checks the User document itself, never trusting the JWT).
  const token = jwt.sign(
    { id: user._id, sid: sessionId, isAdmin: !!user.isAdmin, role: user.role || "user" },
    process.env.JWT_SECRET
  );

  return { token, sessionId, ip, country, deviceId: cleanDeviceId };
}
