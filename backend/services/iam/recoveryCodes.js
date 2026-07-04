/**
 * Phase 9 (IAM): MFA recovery codes - one-time backup codes usable in place of a TOTP code if the
 * user loses their authenticator. Only bcrypt hashes are ever persisted (User.mfa.recoveryCodeHashes);
 * plaintext codes are returned to the caller exactly once, at generation time.
 */
import crypto from "crypto";
import bcrypt from "bcryptjs";

const CODE_COUNT = 10;
const CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // no ambiguous 0/O/1/I

function randomCode() {
  let code = "";
  for (let i = 0; i < 10; i++) {
    if (i === 5) code += "-";
    code += CODE_ALPHABET[crypto.randomInt(CODE_ALPHABET.length)];
  }
  return code;
}

/** @returns {Promise<{plaintextCodes: string[], hashes: string[]}>} */
export async function generateRecoveryCodes(count = CODE_COUNT) {
  const plaintextCodes = Array.from({ length: count }, randomCode);
  const hashes = await Promise.all(plaintextCodes.map((code) => bcrypt.hash(code, 10)));
  return { plaintextCodes, hashes };
}

/**
 * Checks `code` against the stored hashes and, if it matches, returns the remaining hash list
 * with that one removed (recovery codes are single-use). Returns `null` if no hash matched.
 * @returns {Promise<string[] | null>}
 */
export async function consumeRecoveryCode(code, hashes) {
  const normalized = String(code || "").trim().toUpperCase();
  for (let i = 0; i < hashes.length; i++) {
    if (await bcrypt.compare(normalized, hashes[i])) {
      return [...hashes.slice(0, i), ...hashes.slice(i + 1)];
    }
  }
  return null;
}
