/**
 * Phase 7: a curated subset of MITRE ATT&CK techniques relevant to file-borne threats (malware,
 * phishing, credential theft) - NOT the full ATT&CK corpus, which has 600+ techniques. Each entry
 * is keyed by lowercase tag/keyword hints that IOC tags, YARA rule names/descriptions, or DLP
 * detector categories might contain, so mapToMitre() can be driven by whatever signal is
 * available without needing a hand-curated mapping per IOC.
 */
export const MITRE_TECHNIQUES = [
  { techniqueId: "T1059", name: "Command and Scripting Interpreter", tactic: "Execution", keywords: ["script", "powershell", "shell", "cmd", "bash", "macro"] },
  { techniqueId: "T1566", name: "Phishing", tactic: "Initial Access", keywords: ["phishing", "phish", "openphish", "credential"] },
  { techniqueId: "T1204", name: "User Execution", tactic: "Execution", keywords: ["user_execution", "malicious_link", "malicious_file"] },
  { techniqueId: "T1027", name: "Obfuscated Files or Information", tactic: "Defense Evasion", keywords: ["obfuscat", "packed", "encrypted_payload", "encoded"] },
  { techniqueId: "T1071", name: "Application Layer Protocol", tactic: "Command and Control", keywords: ["c2", "command_and_control", "beacon", "http_c2"] },
  { techniqueId: "T1105", name: "Ingress Tool Transfer", tactic: "Command and Control", keywords: ["downloader", "dropper", "transfer"] },
  { techniqueId: "T1041", name: "Exfiltration Over C2 Channel", tactic: "Exfiltration", keywords: ["exfil", "exfiltration"] },
  { techniqueId: "T1486", name: "Data Encrypted for Impact", tactic: "Impact", keywords: ["ransomware", "encrypt_for_impact", "ransom"] },
  { techniqueId: "T1055", name: "Process Injection", tactic: "Defense Evasion", keywords: ["injection", "process_hollowing"] },
  { techniqueId: "T1003", name: "OS Credential Dumping", tactic: "Credential Access", keywords: ["credential_dump", "mimikatz", "lsass"] },
  { techniqueId: "T1082", name: "System Information Discovery", tactic: "Discovery", keywords: ["recon", "system_info"] },
  { techniqueId: "T1053", name: "Scheduled Task/Job", tactic: "Persistence", keywords: ["scheduled_task", "cron", "persistence"] },
  { techniqueId: "T1547", name: "Boot or Logon Autostart Execution", tactic: "Persistence", keywords: ["autostart", "registry_run_key", "startup"] },
  { techniqueId: "T1219", name: "Remote Access Software", tactic: "Command and Control", keywords: ["rat", "remote_access", "trojan"] },
  { techniqueId: "T1190", name: "Exploit Public-Facing Application", tactic: "Initial Access", keywords: ["exploit", "vulnerability", "cve"] }
];

/**
 * @param {string[]} hints - free-text tags/rule names/descriptions to match against keywords
 * @returns {{ techniqueId: string, name: string, tactic: string }[]} deduped matches
 */
export function mapToMitre(hints = []) {
  const haystack = hints.filter(Boolean).map((h) => String(h).toLowerCase());
  if (haystack.length === 0) return [];

  const matches = [];
  for (const technique of MITRE_TECHNIQUES) {
    const hit = technique.keywords.some((kw) => haystack.some((h) => h.includes(kw)));
    if (hit) matches.push({ techniqueId: technique.techniqueId, name: technique.name, tactic: technique.tactic });
  }
  return matches;
}

export function getMitreCatalog() {
  return MITRE_TECHNIQUES.map(({ techniqueId, name, tactic }) => ({ techniqueId, name, tactic }));
}
