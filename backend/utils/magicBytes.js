/**
 * Dependency-free file-type detection by magic bytes (file signature), used to catch a claimed
 * MIME type that doesn't match the file's actual content (e.g. a .pdf that's really a .exe).
 * Deliberately not exhaustive - covers common document/image/archive/executable formats, which
 * is what the risk engine actually needs (dangerous-extension and archive/macro checks lean on
 * the extension too, this is one signal among several, not the sole gate).
 */

const SIGNATURES = [
  { mime: "application/pdf", bytes: [0x25, 0x50, 0x44, 0x46] }, // %PDF
  { mime: "image/png", bytes: [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a] },
  { mime: "image/jpeg", bytes: [0xff, 0xd8, 0xff] },
  { mime: "image/gif", bytes: [0x47, 0x49, 0x46, 0x38, 0x37, 0x61] }, // GIF87a
  { mime: "image/gif", bytes: [0x47, 0x49, 0x46, 0x38, 0x39, 0x61] }, // GIF89a
  { mime: "image/bmp", bytes: [0x42, 0x4d] },
  { mime: "image/webp", bytes: [0x52, 0x49, 0x46, 0x46], offset: 0, extraCheck: (buf) => buf.slice(8, 12).toString("ascii") === "WEBP" },
  { mime: "application/x-msdownload", bytes: [0x4d, 0x5a] }, // MZ - Windows PE (.exe/.dll)
  { mime: "application/x-elf", bytes: [0x7f, 0x45, 0x4c, 0x46] }, // ELF - Linux executable
  { mime: "application/gzip", bytes: [0x1f, 0x8b] },
  { mime: "application/x-rar-compressed", bytes: [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07] },
  { mime: "application/x-7z-compressed", bytes: [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c] },
  { mime: "application/zip", bytes: [0x50, 0x4b, 0x03, 0x04] }, // also docx/xlsx/pptx/jar/apk (all zip-based)
  { mime: "application/zip", bytes: [0x50, 0x4b, 0x05, 0x06] }, // empty zip
  { mime: "text/rtf", bytes: [0x7b, 0x5c, 0x72, 0x74, 0x66] }, // {\rtf
];

/** Returns { mime, hex } for the given buffer, best-effort. Falls back to "text/plain" if the
 *  first bytes look like printable ASCII/UTF-8, else "application/octet-stream". */
export function detectFileType(buffer) {
  const head = buffer.subarray(0, 16);
  const hex = head.toString("hex");

  for (const sig of SIGNATURES) {
    if (head.length < sig.bytes.length) continue;
    const matches = sig.bytes.every((b, i) => head[i] === b);
    if (matches && (!sig.extraCheck || sig.extraCheck(buffer))) {
      return { mime: sig.mime, hex };
    }
  }

  const sample = buffer.subarray(0, 512);
  const printable = sample.every((b) => b === 0x09 || b === 0x0a || b === 0x0d || (b >= 0x20 && b <= 0x7e) || b >= 0x80);
  return { mime: printable ? "text/plain" : "application/octet-stream", hex };
}

/** True if the ZIP local file header's general-purpose bit flag indicates AES/ZipCrypto
 *  encryption (bit 0 of the 2-byte flag field, offset 6-7 within the local file header, which
 *  itself starts right after the 4-byte "PK\x03\x04" signature). Also treats RAR/7z archives as
 *  "encrypted archive" conservatively true only for ZIP, where the flag is cheap to check without
 *  a full parser; RAR/7z encryption detection would need format-specific parsing not worth the
 *  complexity here - they're still flagged as archives via detectFileType for other risk signals. */
export function isEncryptedZip(buffer) {
  if (buffer.length < 8) return false;
  const isZip = buffer[0] === 0x50 && buffer[1] === 0x4b && buffer[2] === 0x03 && buffer[3] === 0x04;
  if (!isZip) return false;
  const flags = buffer.readUInt16LE(6);
  return (flags & 0x1) === 1;
}
