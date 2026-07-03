/**
 * Shared masking helper for DLP findings. Detected secrets/PII are never persisted in full -
 * only a masked preview (enough for a human to recognize "yes, that's the AWS key I meant to
 * remove") is stored on the DLPScan document. This keeps the DLP datastore from becoming a
 * second, unintentional secrets store.
 */
export function maskValue(value) {
  const v = String(value ?? "");
  if (v.length === 0) return "";
  if (v.length <= 4) return "*".repeat(v.length);
  const visible = Math.min(2, Math.floor(v.length / 4));
  return v.slice(0, visible) + "*".repeat(v.length - visible * 2) + v.slice(v.length - visible);
}
