import Session from "../models/Session.js";
import SecurityEvent from "../models/SecurityEvent.js";

/* List the caller's active (non-revoked) sessions (Security Center). */
export const getMySessions = async (req, res) => {
  const sessions = await Session.find({ owner: req.user.id, revoked: false }).sort({ lastActiveAt: -1 });
  res.json(
    sessions.map((s) => ({
      sessionId: s.sessionId,
      deviceId: s.deviceId,
      browser: s.browser,
      operatingSystem: s.operatingSystem,
      ip: s.ip,
      country: s.country,
      createdAt: s.createdAt,
      lastActiveAt: s.lastActiveAt,
      isCurrent: s.sessionId === req.user.sid
    }))
  );
};

/* Revoke a session - the next request bearing that session's token will be rejected by
   auth.middleware.js. Revoking the caller's own current session is allowed (it just logs
   that browser tab out on its next request). */
export const revokeSession = async (req, res) => {
  const { sessionId } = req.params;
  const session = await Session.findOne({ owner: req.user.id, sessionId });
  if (!session) return res.sendStatus(404);

  session.revoked = true;
  await session.save();

  await SecurityEvent.create({
    owner: req.user.id,
    type: "session_revoked",
    message: `Revoked session on ${session.browser || "unknown browser"} (${session.operatingSystem || "unknown OS"})`,
    deviceId: session.deviceId,
    ip: session.ip,
    country: session.country
  });

  res.json({ message: "Session revoked" });
};
