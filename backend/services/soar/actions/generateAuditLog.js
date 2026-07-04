/**
 * Phase 8 (SOAR) action: this app has no separate audit-log store - /audit already reads
 * SecurityEvent documents (see backend/controllers/security.controller.js), so "generating an
 * audit log entry" is implemented as another SecurityEvent, categorized AUTOMATION so it's
 * visually distinguishable from the events a rule was triggered by.
 */
import { logSecurityEvent } from "../../siem/siemLogger.js";

export default async function generateAuditLog(params, event) {
  await logSecurityEvent({
    owner: event.owner,
    type: "automation_triggered",
    message: params?.message || "Automation audit log entry",
    file: event.file,
    filename: event.filename,
    metadata: { auditLog: true, ...params?.metadata }
  });

  return { success: true, detail: "Audit log entry recorded" };
}
