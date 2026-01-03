import mongoose from "mongoose";

const fileSchema = new mongoose.Schema({
  filename: String,
  cloudinaryId: String,

  encryptedKey: String,
  iv: String,

  owner: { type: mongoose.Schema.Types.ObjectId, ref: "User" },

  passwordHash: String,
  oneTime: Boolean,
  revoked: { type: Boolean, default: false },

  expiresAt: Date,
  downloadCount: { type: Number, default: 0 },

  logs: [{ ip: String, time: Date }]
}, { timestamps: true });

export default mongoose.model("File", fileSchema);
