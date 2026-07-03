import SecurityEvent from "../../models/SecurityEvent.js";
import { resolveEventMeta } from "./eventCatalog.js";
import { correlateEvent } from "./correlationEngine.js";

/**
 * Phase 6 (SIEM): the single place that writes SecurityEvent docs. Every controller that used to
 * call `SecurityEvent.create(...)` directly now calls this instead, passing the exact same
 * `type` string (and other fields) as before - severity/category are derived automatically from
 * services/siem/eventCatalog.js unless explicitly overridden. After the event is persisted, the
 * correlation engine is given a chance to group it into an Incident.
 *
 * Never throws - matches the fire-and-forget resilience callers already relied on with
 * `SecurityEvent.create(...).catch(...)`.
 */
export async function logSecurityEvent({
  owner,
  type,
  message,
  file,
  filename,
  deviceId,
  ip,
  country,
  metadata,
  severity,
  category,
  siemType
}) {
  try {
    const meta = resolveEventMeta(type);
    const event = await SecurityEvent.create({
      owner,
      type,
      message,
      file,
      filename,
      deviceId,
      ip,
      country,
      metadata,
      siemType: siemType || meta.siemType,
      severity: severity || meta.severity,
      category: category || meta.category
    });

    await correlateEvent(event);
    return event;
  } catch (err) {
    console.error("Failed to record security event:", err);
    return null;
  }
}
