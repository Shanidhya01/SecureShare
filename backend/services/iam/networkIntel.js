/**
 * Phase 9.5 (IAM adaptive auth): VPN/Tor heuristic detection for the login risk engine.
 *
 * HONEST LIMITATION: this codebase has no commercial IP-intelligence subscription and, per the
 * existing "no external network calls during login" rule (see loginRiskEngine.js and
 * threatIntelEngine.js's hash-only automatic-enrichment rule), does not call any third-party
 * VPN/Tor lookup API here either - that would make every login's latency/availability depend on
 * an external service. Detection is therefore local-only and best-effort:
 *   1. The Phase 7 IOC database (backend/models/IOC.js), if an admin or an external feed has
 *      tagged an IP with "vpn" or "tor" (the same collection Phase 7's threat intel already uses).
 *   2. A small, illustrative static list of well-known Tor directory authority IPs, clearly
 *      documented as non-exhaustive - real coverage should come from importing a maintained
 *      Tor exit-node list into the IOC collection (e.g. a scheduled job hitting
 *      https://check.torproject.org/torbulkexitlist and tagging matches), which is left as a
 *      deployment-time integration rather than a hardcoded, quickly-stale list here.
 */
import IOC from "../../models/IOC.js";

// Illustrative only - a handful of long-standing Tor directory authorities, not a real-time exit
// list. Meant to make the "Tor detected" path demonstrable out of the box; not a security control
// on its own. See header comment for how to wire in real, current data via the IOC collection.
const KNOWN_TOR_DIRECTORY_IPS = new Set([
  "128.31.0.39", // moria1
  "86.59.21.38", // tor26
  "194.109.206.212" // dizum
]);

/** @returns {Promise<{isVpn: boolean, isTor: boolean}>} */
export async function checkNetworkIntel(ip) {
  if (!ip) return { isVpn: false, isTor: false };

  if (KNOWN_TOR_DIRECTORY_IPS.has(ip)) return { isVpn: false, isTor: true };

  const iocHit = await IOC.findOne({ type: "ip", value: ip, status: "active", tags: { $in: ["vpn", "tor"] } }).select("tags");
  if (!iocHit) return { isVpn: false, isTor: false };

  return {
    isVpn: iocHit.tags.includes("vpn"),
    isTor: iocHit.tags.includes("tor")
  };
}
