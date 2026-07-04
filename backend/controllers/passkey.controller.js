import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse
} from "@simplewebauthn/server";
import User from "../models/User.js";
import Passkey from "../models/Passkey.js";
import WebAuthnChallenge from "../models/WebAuthnChallenge.js";
import { issueSessionAndToken } from "../services/iam/sessionIssuer.js";
import { logSecurityEvent } from "../services/siem/siemLogger.js";
import { getClientIp } from "../utils/getClientIp.js";
import { resolveCountry } from "../utils/geoLookup.js";

const RP_ID = process.env.WEBAUTHN_RP_ID || "localhost";
const RP_NAME = process.env.WEBAUTHN_RP_NAME || "SecureShare";
const ORIGIN = process.env.WEBAUTHN_ORIGIN || "http://localhost:3000";

/* REGISTRATION OPTIONS (auth'd) - excludes credentials the user already registered so the same
   authenticator can't be added twice. */
export const registerOptions = async (req, res) => {
  const user = await User.findById(req.user.id);
  if (!user) return res.sendStatus(404);

  const existing = await Passkey.find({ owner: user._id }).select("credentialId transports");

  const options = await generateRegistrationOptions({
    rpName: RP_NAME,
    rpID: RP_ID,
    userName: user.email,
    userDisplayName: user.name || user.email,
    attestationType: "none",
    excludeCredentials: existing.map((p) => ({ id: p.credentialId, transports: p.transports }))
  });

  await WebAuthnChallenge.create({ owner: user._id, challenge: options.challenge, type: "register" });
  res.json(options);
};

/* REGISTRATION VERIFY (auth'd) */
export const registerVerify = async (req, res) => {
  const user = await User.findById(req.user.id);
  if (!user) return res.sendStatus(404);

  const challengeDoc = await WebAuthnChallenge.findOne({ owner: user._id, type: "register" }).sort({ createdAt: -1 });
  if (!challengeDoc) return res.status(400).json({ error: "No pending registration challenge" });

  let verification;
  try {
    verification = await verifyRegistrationResponse({
      response: req.body,
      expectedChallenge: challengeDoc.challenge,
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID
    });
  } catch (err) {
    return res.status(400).json({ error: err.message });
  }

  if (!verification.verified || !verification.registrationInfo) {
    return res.status(400).json({ error: "Passkey verification failed" });
  }

  const { credential, credentialDeviceType, credentialBackedUp } = verification.registrationInfo;
  await Passkey.create({
    owner: user._id,
    credentialId: credential.id,
    publicKey: Buffer.from(credential.publicKey).toString("base64url"),
    counter: credential.counter,
    deviceType: credentialDeviceType,
    backedUp: credentialBackedUp,
    transports: credential.transports || [],
    label: req.body?.label || "Passkey"
  });

  await WebAuthnChallenge.deleteMany({ owner: user._id, type: "register" });
  res.json({ verified: true });
};

/* LIST / REMOVE (auth'd) */
export const listPasskeys = async (req, res) => {
  const passkeys = await Passkey.find({ owner: req.user.id }).select("-publicKey");
  res.json(passkeys);
};

export const removePasskey = async (req, res) => {
  const passkey = await Passkey.findOneAndDelete({ _id: req.params.id, owner: req.user.id });
  if (!passkey) return res.sendStatus(404);
  res.json({ message: "Removed" });
};

/* LOGIN OPTIONS (public) - scoped to the given account's stored credentials. Returns generic
   options even for an unknown email (rather than a distinct 404) to avoid account enumeration. */
export const loginOptions = async (req, res) => {
  const { email } = req.body || {};
  const normalizedEmail = typeof email === "string" ? email.toLowerCase().trim() : "";
  const user = normalizedEmail ? await User.findOne({ email: normalizedEmail }) : null;
  const passkeys = user ? await Passkey.find({ owner: user._id }).select("credentialId transports") : [];

  const options = await generateAuthenticationOptions({
    rpID: RP_ID,
    userVerification: "preferred",
    allowCredentials: passkeys.map((p) => ({ id: p.credentialId, transports: p.transports }))
  });

  await WebAuthnChallenge.create({ email: normalizedEmail || null, challenge: options.challenge, type: "login" });
  res.json(options);
};

/* LOGIN VERIFY (public) - on success, issues a real session via the same issueSessionAndToken()
   every other login path uses. */
export const loginVerify = async (req, res) => {
  const { email, response, deviceId } = req.body || {};
  const normalizedEmail = typeof email === "string" ? email.toLowerCase().trim() : "";
  const user = await User.findOne({ email: normalizedEmail });
  if (!user) return res.status(401).json({ error: "Invalid" });

  const passkey = await Passkey.findOne({ owner: user._id, credentialId: response?.id });
  if (!passkey) return res.status(401).json({ error: "Invalid" });

  const challengeDoc = await WebAuthnChallenge.findOne({ email: normalizedEmail, type: "login" }).sort({ createdAt: -1 });
  if (!challengeDoc) return res.status(400).json({ error: "No pending login challenge" });

  let verification;
  try {
    verification = await verifyAuthenticationResponse({
      response,
      expectedChallenge: challengeDoc.challenge,
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
      credential: {
        id: passkey.credentialId,
        publicKey: Buffer.from(passkey.publicKey, "base64url"),
        counter: passkey.counter,
        transports: passkey.transports
      }
    });
  } catch (err) {
    return res.status(400).json({ error: err.message });
  }

  if (!verification.verified) {
    logSecurityEvent({
      owner: user._id,
      type: "mfa_failed",
      message: "Passkey login failed",
      ip: getClientIp(req),
      country: resolveCountry(req)
    }).catch((e) => console.error("Failed to record security event:", e));
    return res.status(401).json({ error: "Verification failed" });
  }

  passkey.counter = verification.authenticationInfo.newCounter;
  passkey.lastUsedAt = new Date();
  await passkey.save();
  await WebAuthnChallenge.deleteMany({ email: normalizedEmail, type: "login" });

  const { token } = await issueSessionAndToken(user, req, { deviceId, passkeyVerified: true });
  res.json({ token, user: { email: user.email, name: user.name } });
};
