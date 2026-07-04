/**
 * Phase 8 (SOAR) action: blocks further downloads of the triggering file. Shares deleteFile's
 * mechanism (`File.revoked = true`) - kept as a distinct action name for spec compliance/clarity
 * in playbook definitions even though the underlying effect is identical today.
 */
import File from "../../../models/File.js";

export default async function blockDownload(params, event) {
  if (!event.file) return { success: false, detail: "No file associated with triggering event" };

  const file = await File.findByIdAndUpdate(event.file, { revoked: true }, { new: true });
  if (!file) return { success: false, detail: "File not found" };

  return { success: true, detail: `Blocked downloads for "${file.filename}"` };
}
