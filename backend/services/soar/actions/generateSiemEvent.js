/**
 * Phase 8 (SOAR) action: emits an additional SIEM event as a playbook step, bounded to a small
 * allowlist of automation-relevant types (never arbitrary caller-controlled types) so a
 * misconfigured playbook can't forge unrelated event categories.
 */
import { logSecurityEvent } from "../../siem/siemLogger.js";

const ALLOWED_TYPES = [
  "automation_triggered", "automation_skipped", "session_revoked_automatically",
  "file_quarantined_automatically", "user_notified"
];

export default async function generateSiemEvent(params, event) {
  const type = ALLOWED_TYPES.includes(params?.type) ? params.type : "automation_triggered";

  await logSecurityEvent({
    owner: event.owner,
    type,
    message: params?.message || `SOAR playbook step generated a ${type} event`,
    file: event.file,
    filename: event.filename,
    metadata: params?.metadata
  });

  return { success: true, detail: `Generated SIEM event "${type}"` };
}
