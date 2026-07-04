/**
 * Shared plumbing for Phase 7 threat intel providers - a thin https JSON-GET helper (same shape
 * as backend/services/virusTotalLookup.js's private helper) plus the standard "skipped" shape
 * every provider returns when its API key env var isn't set, so a missing key never breaks
 * enrichment or uploads.
 */
import https from "https";

export const SKIPPED = { status: "skipped", confidence: 0, severity: "Low", threatNames: [] };

export function httpsGetJson(hostname, path, headers = {}, timeoutMs = 8000) {
  return new Promise((resolve, reject) => {
    const req = https.request(
      { hostname, path, method: "GET", headers, timeout: timeoutMs },
      (res) => {
        if (res.statusCode === 404) {
          res.resume();
          resolve({ notFoundStatus: true });
          return;
        }
        if (res.statusCode && res.statusCode >= 400) {
          res.resume();
          reject(new Error(`${hostname} API returned status ${res.statusCode}`));
          return;
        }
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => {
          try {
            resolve(JSON.parse(Buffer.concat(chunks).toString("utf8")));
          } catch (e) {
            reject(e);
          }
        });
      }
    );
    req.on("timeout", () => req.destroy(new Error(`${hostname} request timed out`)));
    req.on("error", reject);
    req.end();
  });
}
