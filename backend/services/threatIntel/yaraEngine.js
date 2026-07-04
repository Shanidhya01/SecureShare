/**
 * Phase 7 YARA support. Note: this is a SIMPLIFIED rule matcher, not a native YARA engine -
 * native `yara`/`libyara` Node bindings require a compiled binary that isn't guaranteed to
 * install cleanly across environments, so this implements the practical subset of YARA that
 * matters for this project: a `strings:` section of plain-text/regex patterns and a `condition:`
 * of the form "any of them" / "all of them" / "N of them". Rules are stored as YaraRule documents
 * (backend/models/YaraRule.js) with `ruleSource` in this syntax - see README/SECURITY docs for
 * the exact grammar and why full YARA wasn't used.
 *
 * Only runs against text-extractable content (mirrors dlp/textFileSupport.js's supported-type
 * gate) - binary files are skipped gracefully, never treated as a failure.
 */
import YaraRule from "../../models/YaraRule.js";

/**
 * Parses a minimal rule source of the form:
 *   strings:
 *     $a = "text pattern"
 *     $b = /regex pattern/
 *   condition:
 *     any of them
 */
export function parseRule(ruleSource) {
  const stringsBlock = ruleSource.match(/strings:\s*([\s\S]*?)condition:/i)?.[1] || "";
  const conditionBlock = ruleSource.match(/condition:\s*([\s\S]*)/i)?.[1]?.trim().toLowerCase() || "any of them";

  const patterns = [];
  const lineRe = /\$\w+\s*=\s*(?:"([^"]*)"|\/(.+?)\/([a-z]*))/g;
  let m;
  while ((m = lineRe.exec(stringsBlock))) {
    if (m[1] !== undefined) {
      patterns.push({ kind: "text", value: m[1] });
    } else {
      try {
        patterns.push({ kind: "regex", value: new RegExp(m[2], m[3]?.includes("i") ? "i" : "") });
      } catch {
        // Skip malformed regex patterns rather than failing the whole rule.
      }
    }
  }

  return { patterns, condition: conditionBlock };
}

export function evaluateCondition(condition, matchCount, totalPatterns) {
  if (totalPatterns === 0) return false;
  const nOfThem = condition.match(/^(\d+)\s+of\s+them$/);
  if (condition.includes("all of them")) return matchCount === totalPatterns;
  if (nOfThem) return matchCount >= parseInt(nOfThem[1], 10);
  return matchCount > 0; // default: "any of them"
}

/**
 * @param {string} text - already-extracted plaintext (never raw binary)
 * @returns {Promise<{ skipped: boolean, reason?: string, matches: {ruleName: string, severity: string, mitreTechniques: string[]}[] }>}
 */
export async function runYaraRules(text) {
  if (!text || typeof text !== "string") {
    return { skipped: true, reason: "no_scannable_text", matches: [] };
  }

  const rules = await YaraRule.find({ enabled: true });
  if (rules.length === 0) return { skipped: false, matches: [] };

  const matches = [];
  for (const rule of rules) {
    try {
      const { patterns, condition } = parseRule(rule.ruleSource);
      const matchCount = patterns.filter((p) =>
        p.kind === "text" ? text.includes(p.value) : p.value.test(text)
      ).length;

      if (evaluateCondition(condition, matchCount, patterns.length)) {
        matches.push({ ruleName: rule.name, severity: rule.severity, mitreTechniques: rule.mitreTechniques || [] });
      }
    } catch (err) {
      // A single malformed rule must never take down the whole scan.
      console.error(`YARA rule "${rule.name}" failed to evaluate:`, err);
    }
  }

  return { skipped: false, matches };
}

/** Seeds a handful of example rules if the collection is empty - keeps the feature demonstrable out of the box. */
export async function ensureSeedRules() {
  const count = await YaraRule.countDocuments();
  if (count > 0) return;

  await YaraRule.insertMany([
    {
      name: "Suspicious_PowerShell_EncodedCommand",
      description: "Detects PowerShell's -EncodedCommand flag, commonly used to obfuscate malicious scripts.",
      ruleSource: 'strings:\n  $a = "-EncodedCommand"\n  $b = "-enc "\ncondition:\n  any of them',
      mitreTechniques: ["T1059", "T1027"],
      severity: "High"
    },
    {
      name: "Suspicious_Macro_AutoOpen",
      description: "Detects Office macro auto-execution keywords often used in malicious documents.",
      ruleSource: 'strings:\n  $a = "AutoOpen"\n  $b = "Document_Open"\n  $c = "Shell("\ncondition:\n  2 of them',
      mitreTechniques: ["T1059", "T1204"],
      severity: "High"
    },
    {
      name: "Generic_Ransom_Note_Language",
      description: "Detects common ransom-note phrasing.",
      ruleSource: 'strings:\n  $a = "your files have been encrypted"\n  $b = "bitcoin"\n  $c = "decrypt"\ncondition:\n  2 of them',
      mitreTechniques: ["T1486"],
      severity: "Critical"
    }
  ]);
}
