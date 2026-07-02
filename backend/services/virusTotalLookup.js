/**
 * Optional VirusTotal hash lookup (VT API v3), used as a second opinion alongside ClamAV. Looks
 * up the file's SHA-256 against VT's existing database of previously-analyzed files - it does
 * NOT upload the file itself (keeps this consistent with "never persist/transmit plaintext
 * beyond what's strictly needed for the scan," and avoids VT's slower upload+analyze flow).
 *
 * Entirely optional: if VIRUSTOTAL_API_KEY isn't set, lookups are skipped immediately and the
 * rest of the threat pipeline (ClamAV, magic bytes, risk engine) proceeds without it.
 */
import https from "https";

const VT_HOST = "www.virustotal.com";
const VT_TIMEOUT_MS = 8000;

/**
 * @param {string} sha256
 * @returns {Promise<{status: "skipped"|"clean"|"suspicious"|"malicious"|"unknown"|"error", maliciousCount: number, suspiciousCount: number, totalEngines: number, threatNames: string[]}>}
 */
export async function lookupHashOnVirusTotal(sha256) {
  const apiKey = process.env.VIRUSTOTAL_API_KEY;
  if (!apiKey) {
    return { status: "skipped", maliciousCount: 0, suspiciousCount: 0, totalEngines: 0, threatNames: [] };
  }

  try {
    const body = await httpsGetJson(`/api/v3/files/${sha256}`, apiKey);

    if (body?.notFoundStatus) {
      return { status: "unknown", maliciousCount: 0, suspiciousCount: 0, totalEngines: 0, threatNames: [] };
    }

    const stats = body?.data?.attributes?.last_analysis_stats || {};
    const results = body?.data?.attributes?.last_analysis_results || {};
    const maliciousCount = stats.malicious || 0;
    const suspiciousCount = stats.suspicious || 0;
    const totalEngines = Object.values(stats).reduce((sum, n) => sum + (typeof n === "number" ? n : 0), 0);

    const threatNames = Object.values(results)
      .filter((r) => r?.category === "malicious" && r?.result)
      .map((r) => r.result)
      .slice(0, 10);

    let status = "clean";
    if (maliciousCount > 0) status = "malicious";
    else if (suspiciousCount > 0) status = "suspicious";

    return { status, maliciousCount, suspiciousCount, totalEngines, threatNames };
  } catch (err) {
    return { status: "error", maliciousCount: 0, suspiciousCount: 0, totalEngines: 0, threatNames: [], error: err.message };
  }
}

function httpsGetJson(path, apiKey) {
  return new Promise((resolve, reject) => {
    const req = https.request(
      { hostname: VT_HOST, path, method: "GET", headers: { "x-apikey": apiKey }, timeout: VT_TIMEOUT_MS },
      (res) => {
        if (res.statusCode === 404) {
          res.resume();
          resolve({ notFoundStatus: true });
          return;
        }
        if (res.statusCode && res.statusCode >= 400) {
          res.resume();
          reject(new Error(`VirusTotal API returned status ${res.statusCode}`));
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
    req.on("timeout", () => req.destroy(new Error("VirusTotal request timed out")));
    req.on("error", reject);
    req.end();
  });
}
