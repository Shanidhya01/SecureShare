import express from "express";
import mongoose from "mongoose";
import dotenv from "dotenv";
import cors from "cors";

import authRoutes from "./routes/auth.routes.js";
import fileRoutes from "./routes/file.routes.js";
import ipRoutes from "./routes/ip.routes.js";
import { apiLimiter } from "./middleware/rateLimit.js";

dotenv.config();

const app = express();
app.set("trust proxy", 1); // Trust the first proxy (load balancer, reverse proxy, etc.)
app.use(cors());
app.use(express.json());
app.use("/api", apiLimiter);

mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB connected"));

app.use("/api/auth", authRoutes);
app.use("/api/files", fileRoutes);
app.use("/api", ipRoutes);

// Root and health endpoints
app.get("/", (req, res) => {
  res.send("SecureShare API is running.");
});

app.get("/api/health", (req, res) => {
  res.json({ status: "ok", uptime: process.uptime() });
});

app.listen(5000, () => console.log("Server running"));
