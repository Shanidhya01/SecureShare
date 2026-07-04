/**
 * Phase 8 (SOAR) action: kept as a distinct action name for spec compliance, but no SMTP/email
 * transport exists in this codebase - delegates to the in-app notifyUser action. If real email
 * delivery is added later (e.g. nodemailer), this is the single place to wire it in.
 */
import notifyUser from "./notifyUser.js";

export default async function sendEmail(params, event) {
  const result = await notifyUser(params, event);
  return { ...result, detail: `${result.detail} (sendEmail is an alias - no SMTP transport configured)` };
}
