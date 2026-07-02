import User from "../models/User.js";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

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
    await User.create({
      name: name.trim(),
      email: email.toLowerCase().trim(),
      password: hashed,
      // Optional: base64 SPKI RSA-OAEP public key generated client-side for E2E encryption.
      publicKey: typeof publicKey === "string" && publicKey.length > 0 ? publicKey : undefined,
      // Optional: base64 SPKI ECDSA P-256 public signing key generated client-side (Phase 2).
      signingPublicKey: typeof signingPublicKey === "string" && signingPublicKey.length > 0 ? signingPublicKey : undefined
    });

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
    const { email, password } = req.body;
    const normalizedEmail = typeof email === "string" ? email.toLowerCase().trim() : "";

    if (!normalizedEmail || !password) {
      return res.status(400).json({ error: "Email and password are required" });
    }

    const user = await User.findOne({ email: normalizedEmail });
    if (!user) return res.status(401).json({ error: "Invalid" });

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(401).json({ error: "Invalid" });

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET);
    res.json({ token, user: { email: user.email, name: user.name } });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: err?.message || "Login failed" });
  }
};
