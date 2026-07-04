import jwt from "jsonwebtoken";
import Session from "../models/Session.js";
import { getPolicy } from "../models/SecurityPolicy.js";
import { evaluateSessionTimeout } from "../services/iam/policyEngine.js";

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

      // Phase 9.5 (IAM): configurable session idle timeout - checked against the session's
      // lastActiveAt BEFORE it's refreshed below, so this compares idle time since the previous
      // request, not this one. getPolicy() is short-TTL-cached (see SecurityPolicy.js), so this
      // adds no real DB load to the hot request path.
      const policy = await getPolicy();
      if (evaluateSessionTimeout(policy, session.lastActiveAt).expired) {
        session.revoked = true;
        await session.save();
        return res.status(403).json({ error: "Session expired due to inactivity" });
      }

      session.lastActiveAt = new Date();
      session.save().catch(() => {}); // best-effort, don't block the request on this write
    }

    next();
  } catch {
    res.status(403).json({ error: "Invalid token" });
  }
}
