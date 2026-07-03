/** Phase 3 Zero Trust access policy shape, mirroring backend/models/File.js's `policy` subdocument. */
export type FilePolicy = {
  allowedCountries?: string[];
  allowedIPs?: string[];
  allowedDevices?: string[];
  businessHours?: { enabled?: boolean; startHour?: number; endHour?: number };
  maxDevices?: number;
  requireApproval?: boolean;
} | null;

export function hasZeroTrustPolicy(policy: FilePolicy | undefined): boolean {
  if (!policy) return false;
  return !!(
    (policy.allowedCountries?.length ?? 0) > 0 ||
    (policy.allowedIPs?.length ?? 0) > 0 ||
    policy.businessHours?.enabled ||
    (policy.maxDevices ?? 0) > 0 ||
    policy.requireApproval
  );
}
