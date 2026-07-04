/**
 * Phase 8 (SOAR) action: creates an in-app Notification for every admin account
 * (User.isAdmin === true). Same "no real email" caveat as notifyUser.js applies.
 */
import User from "../../../models/User.js";
import Notification from "../../../models/Notification.js";
import { logSecurityEvent } from "../../siem/siemLogger.js";

export default async function notifyAdmin(params, event) {
  const admins = await User.find({ isAdmin: true }).select("_id");
  if (admins.length === 0) return { success: false, detail: "No admin accounts configured" };

  await Notification.insertMany(
    admins.map((admin) => ({
      owner: admin._id,
      title: params?.title || "Critical automation alert",
      message: params?.message || event.message || "A critical security automation rule fired.",
      severity: params?.severity || event.severity || "HIGH",
      source: "soar",
      relatedFile: event.file || null
    }))
  );

  logSecurityEvent({
    owner: event.owner,
    type: "user_notified",
    message: `${admins.length} administrator(s) notified by automation`,
    file: event.file,
    filename: event.filename
  }).catch(() => {});

  return { success: true, detail: `Notified ${admins.length} administrator(s) (in-app)` };
}
