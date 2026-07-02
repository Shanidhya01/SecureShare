import jwt from "jsonwebtoken";
import Session from "../models/Session.js";

export default async function (req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(403).json({ error: "No token" });

  try {
    const token = authHeader.split(" ")[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;

    // Zero Trust (Phase 3): reject requests whose session has been revoked. Tokens issued
    // before session tracking existed carry no `sid` claim - treat those as untracked legacy
    // sessions and let them through unchanged, since there's nothing to check against.
    if (decoded.sid) {
      const session = await Session.findOne({ sessionId: decoded.sid });
      if (!session || session.revoked) {
        return res.status(403).json({ error: "Session revoked" });
      }
      session.lastActiveAt = new Date();
      session.save().catch(() => {}); // best-effort, don't block the request on this write
    }

    next();
  } catch {
    res.status(403).json({ error: "Invalid token" });
  }
}
