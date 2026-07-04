/**
 * Phase 8 (SOAR) action: quarantines the file associated with the triggering event, using the
 * exact same `File.quarantined`/`ThreatScan.quarantined` fields Phase 4 already reads/writes -
 * no new quarantine mechanism is introduced.
 */
import File from "../../../models/File.js";
import ThreatScan from "../../../models/ThreatScan.js";

export default async function quarantineFile(params, event) {
  if (!event.file) return { success: false, detail: "No file associated with triggering event" };

  const file = await File.findByIdAndUpdate(event.file, { quarantined: true, riskLevel: "Critical" }, { new: true });
  if (!file) return { success: false, detail: "File not found" };

  if (file.scanId) {
    await ThreatScan.findByIdAndUpdate(file.scanId, { quarantined: true }).catch(() => {});
  }

  return { success: true, detail: `Quarantined file "${file.filename}"` };
}
