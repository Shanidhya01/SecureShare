/**
 * abuse.ch URLHaus provider for Phase 7 - malicious URL/domain feed. No API key required, but
 * still gracefully "skipped" if THREAT_INTEL_ENABLE_URLHAUS=false is explicitly set, and on any
 * network/parsing error, consistent with every other provider's contract.
 */
import https from "https";
import { SKIPPED } from "./providerUtils.js";

export const name = "URLHaus";
export const supportedTypes = ["url", "domain"];

export async function lookup(type, value) {
  if (process.env.THREAT_INTEL_ENABLE_URLHAUS === "false") return SKIPPED;
  if (!["url", "domain"].includes(type)) return SKIPPED;

  try {
    const path = type === "url" ? "/api/v1/url/" : "/api/v1/host/";
    const form = type === "url" ? `url=${encodeURIComponent(value)}` : `host=${encodeURIComponent(value)}`;
    const body = await httpsPostForm("urlhaus-api.abuse.ch", path, form);

    if (body?.query_status !== "ok") return { status: "unknown", confidence: 0, severity: "Low", threatNames: [] };

    const threats = type === "url" ? [body.threat] : (body.urls || []).map((u) => u.threat);
    return {
      status: "malicious",
      confidence: 90,
      severity: "Critical",
      threatNames: [...new Set(threats.filter(Boolean))].slice(0, 10)
    };
  } catch (err) {
    return { status: "error", confidence: 0, severity: "Low", threatNames: [], error: err.message };
  }
}

function httpsPostForm(hostname, path, form) {
  return new Promise((resolve, reject) => {
    const data = form;
    const req = https.request(
      {
        hostname,
        path,
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded", "Content-Length": Buffer.byteLength(data) },
        timeout: 8000
      },
      (res) => {
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
    req.on("timeout", () => req.destroy(new Error("URLHaus request timed out")));
    req.on("error", reject);
    req.write(data);
    req.end();
  });
}
