import mongoose from "mongoose";

const fileSchema = new mongoose.Schema({
  filename: String,
  cloudinaryId: String,

  encryptedKey: String,
  iv: String,

  owner: { type: mongoose.Schema.Types.ObjectId, ref: "User" },

  passwordHash: String,
  oneTime: Boolean,
  maxDownloads: { type: Number, default: 1 },
  revoked: { type: Boolean, default: false },

  expiresAt: Date,
  downloadCount: { type: Number, default: 0 },

  // Download logs: who, from where, and when
  logs: [{ ip: String, userEmail: String, time: Date }]
}, { timestamps: true });

export default mongoose.model("File", fileSchema);
