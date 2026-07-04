/**
 * Phase 9 (IAM): thin wrapper over @simplewebauthn/browser's startRegistration/startAuthentication
 * - the official client library that safely handles the ArrayBuffer<->base64url conversions
 * WebAuthn's raw browser API requires, so this codebase doesn't hand-roll that itself.
 */
import { startRegistration, startAuthentication } from "@simplewebauthn/browser";
import api from "@/lib/api";

export async function registerPasskey(token: string, label?: string) {
  const optionsRes = await api.post("/passkeys/register/options", {}, { headers: { Authorization: `Bearer ${token}` } });
  const attestationResponse = await startRegistration({ optionsJSON: optionsRes.data });
  await api.post(
    "/passkeys/register/verify",
    { ...attestationResponse, label },
    { headers: { Authorization: `Bearer ${token}` } }
  );
}

export async function loginWithPasskey(email: string, deviceId?: string) {
  const optionsRes = await api.post("/auth/passkey/options", { email });
  const assertionResponse = await startAuthentication({ optionsJSON: optionsRes.data });
  const verifyRes = await api.post("/auth/passkey/verify", { email, response: assertionResponse, deviceId });
  return verifyRes.data as { token: string; user: { email: string; name: string } };
}
