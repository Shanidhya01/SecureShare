/**
 * Phase 6 (SIEM): correlation engine. `evaluateRules` is pure (no DB access) so it can be unit
 * tested directly - see backend/tests/correlationEngine.test.js. `correlateEvent` is the thin
 * DB-aware wrapper called by siemLogger.js after every new SecurityEvent is persisted.
 *
 * A "match" groups a newly-logged event with earlier related events into an Incident. Rules are
 * intentionally simple, declarative, and backward-looking (they only look at events that already
 * exist by the time the triggering event arrives).
 */

const DAY_MS = 24 * 60 * 60 * 1000;
const HOUR_MS = 60 * 60 * 1000;

const sameFile = (a, b) => a && b && String(a) === String(b);

/**
 * @param {Array<{_id:string, siemType?:string, severity?:string, file?:string, createdAt:Date}>} recentEvents
 *   All of the owner's events from the last 24h, oldest first, INCLUDING the new event.
 * @param {{_id:string, siemType?:string, severity?:string, file?:string, createdAt:Date}} newEvent
 * @returns {Array<{ruleId:string, title:string, summary:string, category:string, severity:string, file?:string, matchedEventIds:string[]}>}
 */
export function evaluateRules(recentEvents, newEvent) {
  const matches = [];
  const before = recentEvents.filter((e) => String(e._id) !== String(newEvent._id));

  // Rule 1: malware quarantined/flagged, later a download of that same file was denied.
  if (newEvent.siemType === "DOWNLOAD_DENIED" && newEvent.file) {
    const quarantineEvents = before.filter(
      (e) =>
        sameFile(e.file, newEvent.file) &&
        newEvent.createdAt - e.createdAt <= DAY_MS &&
        (e.siemType === "FILE_QUARANTINED" || (e.siemType === "THREAT_FOUND" && ["HIGH", "CRITICAL"].includes(e.severity)))
    );
    if (quarantineEvents.length > 0) {
      matches.push({
        ruleId: "malware-blocked-download",
        title: "Malware upload blocked from further access",
        summary: "A quarantined/high-risk file was later denied for download - the block held.",
        category: "THREAT",
        severity: "CRITICAL",
        file: newEvent.file,
        matchedEventIds: [...quarantineEvents.map((e) => e._id), newEvent._id]
      });
    }
  }

  // Rule 2: 3+ DLP blocks/warnings for the same owner within the last hour.
  if (newEvent.siemType === "DLP_BLOCK" || newEvent.siemType === "DLP_WARNING") {
    const dlpEvents = recentEvents.filter(
      (e) =>
        (e.siemType === "DLP_BLOCK" || e.siemType === "DLP_WARNING") &&
        newEvent.createdAt - e.createdAt <= HOUR_MS
    );
    if (dlpEvents.length >= 3) {
      matches.push({
        ruleId: "repeated-dlp-violations",
        title: "Repeated DLP policy violations",
        summary: `${dlpEvents.length} DLP policy violations within the last hour.`,
        category: "DLP",
        severity: "HIGH",
        matchedEventIds: dlpEvents.map((e) => e._id)
      });
    }
  }

  // Rule 3: a new device appeared, then access was denied for this owner within the hour.
  if (newEvent.siemType === "DOWNLOAD_DENIED" || newEvent.siemType === "POLICY_VIOLATION") {
    const deviceEvents = before.filter(
      (e) => e.siemType === "DEVICE_NEW" && newEvent.createdAt - e.createdAt <= HOUR_MS
    );
    if (deviceEvents.length > 0) {
      matches.push({
        ruleId: "new-device-then-denied",
        title: "New device followed by a blocked access attempt",
        summary: "A newly trusted device attempted (and was denied) access shortly after being added.",
        category: "ZERO_TRUST",
        severity: "MEDIUM",
        matchedEventIds: [...deviceEvents.map((e) => e._id), newEvent._id]
      });
    }
  }

  return matches;
}

/**
 * DB-aware wrapper: loads the owner's last 24h of events, evaluates the rules, and either
 * appends to an existing open Incident (same rule + owner + file, still within its own 24h
 * window) or creates a new one. Never throws - correlation is best-effort and must never block
 * the write path that triggered it.
 */
export async function correlateEvent(event) {
  try {
    const SecurityEvent = (await import("../../models/SecurityEvent.js")).default;
    const Incident = (await import("../../models/Incident.js")).default;

    const since = new Date(event.createdAt.getTime() - DAY_MS);
    const recentEvents = await SecurityEvent.find({
      owner: event.owner,
      createdAt: { $gte: since, $lte: event.createdAt }
    })
      .sort({ createdAt: 1 })
      .select("_id siemType severity file createdAt")
      .lean();

    const matches = evaluateRules(recentEvents, {
      _id: event._id,
      siemType: event.siemType,
      severity: event.severity,
      file: event.file,
      createdAt: event.createdAt
    });

    for (const match of matches) {
      const existing = await Incident.findOne({
        owner: event.owner,
        ruleId: match.ruleId,
        file: match.file || null,
        status: { $ne: "resolved" },
        lastEventAt: { $gte: since }
      });

      if (existing) {
        const newIds = match.matchedEventIds.filter(
          (id) => !existing.events.some((e) => String(e) === String(id))
        );
        existing.events.push(...newIds);
        existing.eventCount = existing.events.length;
        existing.lastEventAt = event.createdAt;
        await existing.save();
        await SecurityEvent.updateMany({ _id: { $in: newIds } }, { correlationId: String(existing._id) });
      } else {
        const incident = await Incident.create({
          owner: event.owner,
          ruleId: match.ruleId,
          title: match.title,
          summary: match.summary,
          category: match.category,
          severity: match.severity,
          file: match.file || undefined,
          events: match.matchedEventIds,
          eventCount: match.matchedEventIds.length,
          firstEventAt: recentEvents[0]?.createdAt || event.createdAt,
          lastEventAt: event.createdAt
        });
        await SecurityEvent.updateMany(
          { _id: { $in: match.matchedEventIds } },
          { correlationId: String(incident._id) }
        );
      }
    }
  } catch (err) {
    console.error("SIEM correlation error:", err);
  }
}
