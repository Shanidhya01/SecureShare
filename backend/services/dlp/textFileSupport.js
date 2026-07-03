/**
 * Determines whether a file is eligible for DLP content scanning (text-based only) and, if so,
 * safely decodes it to a string. Binary files (images, video, executables, most archives) are
 * skipped gracefully - there is no reliable text content to scan, and attempting to regex a
 * binary buffer risks both false positives and wasted CPU. Mirrors the dependency-free style of
 * backend/utils/magicBytes.js.
 */
import { getFileExtension } from "../riskEngine.js";

const TEXT_EXTENSIONS = new Set([
  ".txt", ".csv", ".tsv", ".log", ".md", ".markdown", ".json", ".yml", ".yaml", ".xml", ".ini",
  ".conf", ".config", ".env", ".sql", ".js", ".jsx", ".ts", ".tsx", ".py", ".java", ".rb", ".go",
  ".php", ".c", ".cpp", ".h", ".hpp", ".cs", ".html", ".htm", ".css", ".scss", ".sh", ".ps1",
  ".bat", ".properties", ".toml", ".pem", ".crt", ".key", ".cer"
]);

const TEXT_MIME_PREFIXES = ["text/"];
const TEXT_MIME_EXACT = new Set([
  "application/json",
  "application/xml",
  "application/x-yaml",
  "application/x-sh",
  "application/javascript"
]);

// Cap how much content is scanned per file - large text files are read up to this many bytes,
// which is plenty for detecting embedded secrets while keeping regex scan time bounded.
export const MAX_SCAN_BYTES = 5 * 1024 * 1024; // 5MB

function isTextMime(mime) {
  if (!mime) return false;
  const lower = mime.toLowerCase();
  return TEXT_MIME_EXACT.has(lower) || TEXT_MIME_PREFIXES.some((p) => lower.startsWith(p));
}

/** Best-effort printable-content heuristic, same approach as magicBytes.js's detectFileType. */
function looksLikeText(buffer) {
  const sample = buffer.subarray(0, 1024);
  if (sample.length === 0) return true;
  let printable = 0;
  for (const b of sample) {
    if (b === 0x09 || b === 0x0a || b === 0x0d || (b >= 0x20 && b <= 0x7e) || b >= 0x80) printable++;
  }
  return printable / sample.length > 0.95;
}

/**
 * @param {Buffer} buffer
 * @param {{ originalFilename: string, claimedMimeType?: string, detectedMimeType?: string }} meta
 * @returns {{ supported: boolean, reason?: string, text?: string, truncated?: boolean }}
 */
export function extractScannableText(buffer, { originalFilename, claimedMimeType, detectedMimeType }) {
  const extension = getFileExtension(originalFilename);
  const extensionSaysText = TEXT_EXTENSIONS.has(extension);
  const mimeSaysText = isTextMime(claimedMimeType) || isTextMime(detectedMimeType);

  if (!extensionSaysText && !mimeSaysText && !looksLikeText(buffer)) {
    return { supported: false, reason: "binary_or_unsupported_type" };
  }

  const truncated = buffer.length > MAX_SCAN_BYTES;
  const slice = truncated ? buffer.subarray(0, MAX_SCAN_BYTES) : buffer;

  let text;
  try {
    text = slice.toString("utf8");
  } catch {
    return { supported: false, reason: "decode_failed" };
  }

  return { supported: true, text, truncated };
}
