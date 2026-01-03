import express from "express";
import mongoose from "mongoose";
import dotenv from "dotenv";
import cors from "cors";

import authRoutes from "./routes/auth.routes.js";
import fileRoutes from "./routes/file.routes.js";
import { apiLimiter } from "./middleware/rateLimit.js";

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());
app.use("/api", apiLimiter);

mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB connected"));

app.use("/api/auth", authRoutes);
app.use("/api/files", fileRoutes);

app.listen(5000, () => console.log("Server running"));
