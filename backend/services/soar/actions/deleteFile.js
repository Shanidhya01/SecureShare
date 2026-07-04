/**
 * Phase 8 (SOAR) action: "delete" is a soft-delete via `File.revoked = true`, the same field
 * already used for expired/limit-reached files in file.controller.js's download path - no hard
 * Mongo deletion, so file metadata/audit history is preserved.
 */
import File from "../../../models/File.js";

export default async function deleteFile(params, event) {
  if (!event.file) return { success: false, detail: "No file associated with triggering event" };

  const file = await File.findByIdAndUpdate(event.file, { revoked: true }, { new: true });
  if (!file) return { success: false, detail: "File not found" };

  return { success: true, detail: `Revoked (soft-deleted) file "${file.filename}"` };
}
