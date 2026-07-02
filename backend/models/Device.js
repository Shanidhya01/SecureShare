import mongoose from "mongoose";

/**
 * A device a user has successfully logged in from. `deviceId` is a client-generated,
 * privacy-preserving fingerprint hash (see frontend/lib/security/fingerprint.ts) - the server
 * never receives or stores the raw browser attributes it was derived from, only the resulting
 * hash. Trust is bootstrapped at login time: a device that successfully authenticates with the
 * account's password is marked trusted (see backend/controllers/auth.controller.js).
 */
const deviceSchema = new mongoose.Schema(
  {
    owner: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    deviceId: { type: String, required: true },

    label: String,            // e.g. "Chrome on Windows"
    browser: String,
    operatingSystem: String,
    userAgent: String,

    firstSeenAt: { type: Date, default: Date.now },
    lastSeenAt: { type: Date, default: Date.now },
    lastIp: String,

    trusted: { type: Boolean, default: true },
    revoked: { type: Boolean, default: false }
  },
  { timestamps: true }
);

deviceSchema.index({ owner: 1, deviceId: 1 }, { unique: true });

export default mongoose.model("Device", deviceSchema);
