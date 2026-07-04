import File from "../../../models/File.js";

export default async function markFileHighRisk(params, event) {
  if (!event.file) return { success: false, detail: "No file associated with triggering event" };

  const file = await File.findByIdAndUpdate(event.file, { riskLevel: "Critical" }, { new: true });
  if (!file) return { success: false, detail: "File not found" };

  return { success: true, detail: `Marked "${file.filename}" as high risk` };
}
