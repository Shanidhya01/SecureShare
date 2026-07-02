import SecurityEvent from "../models/SecurityEvent.js";

/* Recent security activity for the Security Center: new-device logins, device removals,
   session revocations, and denied download attempts against the caller's own files
   ("blocked access attempts" - type: "download_denied"). */
export const getMySecurityEvents = async (req, res) => {
  const events = await SecurityEvent.find({ owner: req.user.id }).sort({ createdAt: -1 }).limit(100);
  res.json(
    events.map((e) => ({
      id: e._id,
      type: e.type,
      message: e.message,
      filename: e.filename || null,
      fileId: e.file || null,
      deviceId: e.deviceId || null,
      ip: e.ip || null,
      country: e.country || null,
      createdAt: e.createdAt
    }))
  );
};
