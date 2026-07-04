import express from "express";
import mongoose from "mongoose";
import dotenv from "dotenv";
import cors from "cors";
import cron from "node-cron";

import authRoutes from "./routes/auth.routes.js";
import fileRoutes from "./routes/file.routes.js";
import userRoutes from "./routes/user.routes.js";
import deviceRoutes from "./routes/device.routes.js";
import sessionRoutes from "./routes/session.routes.js";
import securityRoutes from "./routes/security.routes.js";
import threatRoutes from "./routes/threat.routes.js";
import dlpRoutes from "./routes/dlp.routes.js";
import siemRoutes from "./routes/siem.routes.js";
import threatIntelRoutes from "./routes/threatIntel.routes.js";
import soarRoutes from "./routes/soar.routes.js";
import mfaRoutes from "./routes/mfa.routes.js";
import passkeyRoutes, { passkeyLoginRouter } from "./routes/passkey.routes.js";
import iamRoutes from "./routes/iam.routes.js";
import ipRoutes from "./routes/ip.routes.js";
import complianceRoutes from "./routes/compliance.routes.js";
import cloudRoutes from "./routes/cloud.routes.js";
import { apiLimiter } from "./middleware/rateLimit.js";
import { ensureSeedRules } from "./services/threatIntel/yaraEngine.js";
import { ensureSeedPlaybooks } from "./services/soar/seedPlaybooks.js";
import { ensureSeedFrameworks } from "./services/compliance/seedFrameworks.js";
import { runAssessment } from "./services/compliance/complianceEngine.js";
import { runCloudScan } from "./services/cloud/cloudScanOrchestrator.js";
import User from "./models/User.js";

dotenv.config();

const app = express();
app.set("trust proxy", 1); // Trust the first proxy (load balancer, reverse proxy, etc.)
app.use(cors());
app.use(express.json());
app.use("/api", apiLimiter);

if (!process.env.MONGO_URI) {
  console.error("MongoDB connection error: MONGO_URI is not set in backend/.env");
} else {
  mongoose
    .connect(process.env.MONGO_URI)
    .then(() => {
      console.log("MongoDB connected");
      ensureSeedRules().catch((err) => console.error("Failed to seed YARA rules:", err.message));
      ensureSeedPlaybooks().catch((err) => console.error("Failed to seed SOAR playbooks:", err.message));
      ensureSeedFrameworks().catch((err) => console.error("Failed to seed compliance frameworks:", err.message));
      scheduleDailyComplianceScan();
      scheduleDailyCloudScan();
      runStartupCloudScan();
    })
    .catch((err) => console.error("MongoDB connection error:", err.message));
}

mongoose.connection.on("error", (err) => {
  console.error("MongoDB connection error (post-connect):", err.message);
});

app.use("/api/auth", authRoutes);
app.use("/api/files", fileRoutes);
app.use("/api/users", userRoutes);
app.use("/api/devices", deviceRoutes);
app.use("/api/sessions", sessionRoutes);
app.use("/api/security", securityRoutes);
app.use("/api/threats", threatRoutes);
app.use("/api/dlp", dlpRoutes);
app.use("/api/siem", siemRoutes);
app.use("/api/threat-intel", threatIntelRoutes);
app.use("/api/soar", soarRoutes);
app.use("/api/mfa", mfaRoutes);
app.use("/api/passkeys", passkeyRoutes);
app.use("/api/auth/passkey", passkeyLoginRouter);
app.use("/api/iam", iamRoutes);
app.use("/api/compliance", complianceRoutes);
app.use("/api/cloud", cloudRoutes);
app.use("/api", ipRoutes);

// Phase 10 (Compliance & Governance): continuous compliance - re-run the full assessment once a
// day at 03:00 server time, using `node-cron` (already a dependency, previously only wired up in
// the unused backend/cron/cleanup.js). Attributed to the first admin account found so the
// resulting SIEM events have a valid `owner` (SecurityEvent.owner is required); silently skipped
// if no admin exists yet.
function scheduleDailyComplianceScan() {
  cron.schedule("0 3 * * *", async () => {
    try {
      const admin = await User.findOne({ $or: [{ isAdmin: true }, { role: { $in: ["administrator", "org_owner"] } }] }).select("_id");
      if (!admin) return;
      await runAssessment({ owner: admin._id });
    } catch (err) {
      console.error("Scheduled compliance scan failed:", err.message);
    }
  });
}

// Phase 11 (CSPM/ASM): continuous posture scanning - one daily scan (offset from Compliance's
// 03:00 slot) plus a one-off scan ~10s after every server startup/deployment, both attributed to
// the first admin account exactly like scheduleDailyComplianceScan(). Config/policy-change and
// "on deploy" triggers (PART 10) are satisfied by the manual POST /api/cloud/scan endpoint, which
// a deploy pipeline or the policy-update handlers can call - there's no reliable way to detect
// "a deploy just happened" from inside the already-running process it deployed.
function scheduleDailyCloudScan() {
  cron.schedule("0 4 * * *", async () => {
    try {
      const admin = await User.findOne({ $or: [{ isAdmin: true }, { role: { $in: ["administrator", "org_owner"] } }] }).select("_id");
      if (!admin) return;
      await runCloudScan({ owner: admin._id });
    } catch (err) {
      console.error("Scheduled cloud scan failed:", err.message);
    }
  });
}

function runStartupCloudScan() {
  setTimeout(async () => {
    try {
      const admin = await User.findOne({ $or: [{ isAdmin: true }, { role: { $in: ["administrator", "org_owner"] } }] }).select("_id");
      if (!admin) return;
      await runCloudScan({ owner: admin._id });
    } catch (err) {
      console.error("Startup cloud scan failed:", err.message);
    }
  }, 10000);
}

// Root and health endpoints
app.get("/", (req, res) => {
  res.send("SecureShare API is running.");
});

app.get("/api/health", (req, res) => {
  res.json({ status: "ok", uptime: process.uptime() });
});

app.listen(5000, () => console.log("Server running"));
