import { isAxiosError } from "axios";

/** Extracts a human-readable message from an unknown catch-block error, matching this app's
 *  convention of preferring `response.data.error`/`response.data.message` from the backend. */
export function apiErrorMessage(err: unknown, fallback: string): string {
  if (isAxiosError(err)) {
    const data = err.response?.data as { error?: string; message?: string } | undefined;
    return data?.error || data?.message || fallback;
  }
  if (err instanceof Error) return err.message || fallback;
  return fallback;
}

export function apiErrorStatus(err: unknown): number | undefined {
  return isAxiosError(err) ? err.response?.status : undefined;
}

/** Extracts the backend's short `error` code field (e.g. "revoked", "expired", "not_found"),
 *  distinct from apiErrorMessage's human-readable text. */
export function apiErrorCode(err: unknown): string | undefined {
  if (!isAxiosError(err)) return undefined;
  const data = err.response?.data as { error?: string } | undefined;
  return data?.error;
}
