/**
 * Client-side device fingerprinting for Zero Trust device trust (Phase 3).
 *
 * Generates a stable device identifier by hashing a fixed set of browser attributes (user
 * agent, platform, language, timezone, screen resolution, and a canvas rendering fingerprint).
 * Deliberately privacy-minimal: no raw attribute values ever leave the browser, only the
 * resulting SHA-256 hash - the server can recognize "this same device logged in before" without
 * storing the underlying fingerprint data (which would be far more sensitive/identifying than a
 * one-way hash). None of the inputs are personally-identifying beyond what's already visible to
 * the server in every request's User-Agent header anyway.
 */
import { sha256Base64 } from "@/lib/crypto/cryptoHelpers";

function getCanvasFingerprint(): string {
  try {
    const canvas = document.createElement("canvas");
    const ctx = canvas.getContext("2d");
    if (!ctx) return "no-canvas";
    ctx.textBaseline = "top";
    ctx.font = "14px 'Arial'";
    ctx.fillStyle = "#f60";
    ctx.fillRect(125, 1, 62, 20);
    ctx.fillStyle = "#069";
    ctx.fillText("SecureShare fp", 2, 15);
    ctx.fillStyle = "rgba(102, 204, 0, 0.7)";
    ctx.fillText("SecureShare fp", 4, 17);
    return canvas.toDataURL();
  } catch {
    return "canvas-unavailable";
  }
}

function collectDeviceAttributes(): string[] {
  return [
    navigator.userAgent || "unknown-ua",
    navigator.platform || "unknown-platform",
    navigator.language || "unknown-lang",
    Intl.DateTimeFormat().resolvedOptions().timeZone || "unknown-tz",
    `${screen.width}x${screen.height}x${screen.colorDepth}`,
    getCanvasFingerprint(),
  ];
}

/** Computes a stable device identifier for this browser. Deterministic - the same browser on
 *  the same device produces the same hash every time, without persisting anything locally. */
export async function getDeviceId(): Promise<string> {
  const raw = collectDeviceAttributes().join("|");
  const bytes = new TextEncoder().encode(raw);
  return sha256Base64(bytes);
}
