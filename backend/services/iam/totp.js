/**
 * Phase 9 (IAM): thin wrapper over otplib v13's free-function API (no `authenticator` object in
 * this major version - see https://github.com/yeojz/otplib's v13 changelog). Isolated here so
 * the rest of the codebase never depends on otplib's exact API shape directly.
 */
import { generateSecret as otplibGenerateSecret, generate, verify, generateURI } from "otplib";

export function generateSecret() {
  return otplibGenerateSecret();
}

/** @returns {Promise<string>} current 6-digit TOTP code for this secret - used by tests only */
export async function generateToken(secret) {
  return generate({ secret });
}

/** @returns {Promise<boolean>} */
export async function verifyToken(token, secret) {
  if (!token || !secret) return false;
  try {
    const result = await verify({ token: String(token).trim(), secret });
    return !!result?.valid;
  } catch {
    return false;
  }
}

export function buildOtpauthUri(secret, accountEmail, issuer = "SecureShare") {
  return generateURI({ issuer, label: accountEmail, secret });
}
