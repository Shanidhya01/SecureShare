/**
 * Phase 8 (SOAR) action: creates an in-app Notification for the triggering event's owner, plus a
 * `user_notified` SIEM event. No SMTP/email transport exists anywhere in this codebase (checked
 * during Phase 8 research) - this is genuinely an in-app notification, not real email.
 */
import Notification from "../../../models/Notification.js";
import { logSecurityEvent } from "../../siem/siemLogger.js";

export default async function notifyUser(params, event) {
  await Notification.create({
    owner: event.owner,
    title: params?.title || "Security automation notice",
    message: params?.message || event.message || "A security automation rule affected your account.",
    severity: params?.severity || event.severity || "INFO",
    source: "soar",
    relatedFile: event.file || null
  });

  logSecurityEvent({
    owner: event.owner,
    type: "user_notified",
    message: params?.message || "User notified by automation",
    file: event.file,
    filename: event.filename
  }).catch(() => {});

  return { success: true, detail: "Notified user (in-app)" };
}
