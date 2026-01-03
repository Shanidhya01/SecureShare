import mongoose from "mongoose";

const fileSchema = new mongoose.Schema({
  filename: String,
  encryptedKey: String,
  owner: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  expiresAt: Date,
  oneTime: Boolean,
  downloadCount: { type: Number, default: 0 },
  logs: [
    {
      ip: String,
      time: Date
    }
  ]
});

export default mongoose.model("File", fileSchema);
