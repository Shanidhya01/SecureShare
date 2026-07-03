import crypto from "crypto";
import User from "../models/User.js";
import Device from "../models/Device.js";
import Session from "../models/Session.js";
import { logSecurityEvent } from "../services/siem/siemLogger.js";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { parseUserAgent } from "../utils/deviceContext.js";
import { resolveCountry } from "../utils/geoLookup.js";
import { getClientIp } from "../utils/getClientIp.js";

export const register = async (req, res) => {
  try {
    const { name, email, password, publicKey, signingPublicKey } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ error: "Name, email, and password are required" });
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
    if (!ok) return res.status(401).json({ error: "Invalid" });

    // Zero Trust (Phase 3): a successful password check bootstraps trust for this device -
    // record/refresh it, and track this login as a revocable session.
    const ip = getClientIp(req);
    const country = resolveCountry(req);
    const { browser, operatingSystem } = parseUserAgent(req.headers["user-agent"]);
    const cleanDeviceId = typeof deviceId === "string" && deviceId.length > 0 ? deviceId : undefined;

    if (cleanDeviceId) {
      const existingDevice = await Device.findOne({ owner: user._id, deviceId: cleanDeviceId });
      if (existingDevice) {
        existingDevice.lastSeenAt = new Date();
        existingDevice.lastIp = ip;
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
          trusted: true
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

    // Phase 6 (SIEM): surface every successful login and the session it created in the unified
    // event feed - previously only first-time devices were logged at all.
    logSecurityEvent({
      owner: user._id,
      type: "login",
      message: `Signed in from ${browser} on ${operatingSystem}`,
      deviceId: cleanDeviceId,
      ip,
      country
    }).catch((e) => console.error("Failed to record security event:", e));
    logSecurityEvent({
      owner: user._id,
      type: "session_created",
      message: `New session started on ${browser} on ${operatingSystem}`,
      deviceId: cleanDeviceId,
      ip,
      country
    }).catch((e) => console.error("Failed to record security event:", e));

    const token = jwt.sign({ id: user._id, sid: sessionId }, process.env.JWT_SECRET);
    res.json({ token, user: { email: user.email, name: user.name } });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: err?.message || "Login failed" });
  }
};
