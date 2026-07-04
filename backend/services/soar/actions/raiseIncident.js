/**
 * Phase 8 (SOAR) action: creates a standalone Incident tagged category "AUTOMATION" - distinct
 * from the ones backend/services/siem/correlationEngine.js creates from correlated event
 * patterns, this is an explicit escalation a playbook step requests regardless of correlation.
 */
import Incident from "../../../models/Incident.js";

export default async function raiseIncident(params, event) {
  const incident = await Incident.create({
    owner: event.owner,
    ruleId: `soar-manual-${params?.ruleId || "escalation"}`,
    title: params?.title || "Automation-raised incident",
    summary: params?.summary || event.message || "Raised by a SOAR playbook step.",
    category: "AUTOMATION",
    severity: params?.severity || event.severity || "MEDIUM",
    file: event.file || undefined,
    events: event._id ? [event._id] : [],
    eventCount: event._id ? 1 : 0,
    firstEventAt: event.createdAt || new Date(),
    lastEventAt: event.createdAt || new Date(),
    automationStatus: "triggered"
  });

  return { success: true, detail: `Raised incident "${incident.title}"`, incidentId: incident._id };
}
