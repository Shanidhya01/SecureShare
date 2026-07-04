/**
 * Phase 9 (IAM/SOAR integration) action: sets a one-shot step-up flag on the account tied to the
 * triggering event. backend/controllers/auth.controller.js's login() checks
 * `User.forceMfaOnNextLogin` and, if the user has MFA enrolled, forces the challenge even on an
 * otherwise MFA-trusted device (emitting STEP_UP_AUTH); if the user has no MFA enrolled, login
 * still proceeds but the response flags `mfaSetupRequired: true` - this app has no account-lockout
 * flow, so "require MFA" is enforced as a forced step-up where possible and a strong nudge
 * otherwise, consistent with services/iam/policyEngine.js's soft-block design.
 */
import User from "../../../models/User.js";

export default async function requireMfaStepUp(params, event) {
  if (!event.owner) return { success: false, detail: "No owner associated with triggering event" };

  const user = await User.findByIdAndUpdate(event.owner, { forceMfaOnNextLogin: true }, { new: true });
  if (!user) return { success: false, detail: "User not found" };

  return {
    success: true,
    detail: user.mfa?.enabled
      ? "MFA step-up required on next login"
      : "MFA not enrolled - next login will flag mfaSetupRequired instead of forcing a challenge"
  };
}
