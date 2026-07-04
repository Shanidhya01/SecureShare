/**
 * CIRCL (Computer Incident Response Center Luxembourg) provider for Phase 7 - uses CIRCL's free
 * public hash-lookup service (hashlookup.circl.lu) to check whether a hash is a KNOWN-GOOD file
 * (NSRL dataset), which is a useful negative signal alongside the malicious-focused providers
 * above. No API key required; gracefully skips on any error.
 */
import { httpsGetJson } from "./providerUtils.js";

export const name = "CIRCL";
export const supportedTypes = ["sha256", "sha1", "md5"];

export async function lookup(type, value) {
  if (process.env.THREAT_INTEL_ENABLE_CIRCL === "false") return { status: "skipped", confidence: 0, severity: "Low", threatNames: [] };
  if (!supportedTypes.includes(type)) return { status: "skipped", confidence: 0, severity: "Low", threatNames: [] };

  try {
    const body = await httpsGetJson("hashlookup.circl.lu", `/lookup/${type}/${value}`);
    if (body?.notFoundStatus || !body || body.message === "Non existing SHA-1") {
      return { status: "unknown", confidence: 0, severity: "Low", threatNames: [] };
    }
    // Present in NSRL => known-good software, not a threat signal.
    return { status: "clean", confidence: 90, severity: "Low", threatNames: [] };
  } catch (err) {
    return { status: "error", confidence: 0, severity: "Low", threatNames: [], error: err.message };
  }
}
