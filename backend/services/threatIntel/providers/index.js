/**
 * Registry of all Phase 7 threat intel providers - mirrors backend/services/dlp/detectors/
 * index.js's DETECTORS pattern. Adding a new provider is just adding a file here and importing
 * it below; backend/services/threatIntel/iocLookupService.js iterates this list generically.
 */
import * as virusTotal from "./virusTotalProvider.js";
import * as abuseIpdb from "./abuseIpdbProvider.js";
import * as alienVaultOtx from "./alienVaultOtxProvider.js";
import * as urlhaus from "./urlhausProvider.js";
import * as openPhish from "./openPhishProvider.js";
import * as circl from "./circlProvider.js";

export const PROVIDERS = [virusTotal, abuseIpdb, alienVaultOtx, urlhaus, openPhish, circl];
