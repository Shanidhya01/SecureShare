/**
 * Composite 0-100 security score derived entirely from data the app already fetches
 * (devices, threat stats, DLP stats, file signing/policy usage). There is no backend
 * endpoint for this - it's a client-side rollup so Dashboard and Security Center can
 * show a consistent number from the same inputs.
 */
export type SecurityScoreInputs = {
  totalDevices: number;
  trustedDevices: number;
  totalScans: number;
  malwareDetections: number;
  quarantinedFiles: number;
  dlpTotalScans: number;
  dlpViolations: number;
  totalFiles: number;
  signedFiles: number;
  policiesConfigured: number;
};

export type SecurityScoreBand = "Excellent" | "Good" | "Needs Attention";

export function computeSecurityScore(inputs: SecurityScoreInputs): number {
  const {
    totalDevices,
    trustedDevices,
    totalScans,
    malwareDetections,
    quarantinedFiles,
    dlpTotalScans,
    dlpViolations,
    totalFiles,
    signedFiles,
    policiesConfigured,
  } = inputs;

  const deviceTrustRatio = totalDevices > 0 ? trustedDevices / totalDevices : 1;
  const malwareCleanRatio = totalScans > 0 ? 1 - malwareDetections / totalScans : 1;
  const quarantineRatio = totalFiles > 0 ? 1 - quarantinedFiles / totalFiles : 1;
  const dlpCleanRatio = dlpTotalScans > 0 ? 1 - dlpViolations / dlpTotalScans : 1;
  const signatureRatio = totalFiles > 0 ? signedFiles / totalFiles : 0.5;
  const policyRatio = totalFiles > 0 ? Math.min(1, policiesConfigured / totalFiles) : 0;

  const weighted =
    deviceTrustRatio * 0.2 +
    malwareCleanRatio * 0.25 +
    quarantineRatio * 0.15 +
    dlpCleanRatio * 0.2 +
    signatureRatio * 0.1 +
    policyRatio * 0.1;

  return Math.round(Math.max(0, Math.min(1, weighted)) * 100);
}

export function scoreBand(score: number): SecurityScoreBand {
  if (score >= 85) return "Excellent";
  if (score >= 60) return "Good";
  return "Needs Attention";
}

export function scoreColor(score: number): string {
  if (score >= 85) return "#10B981";
  if (score >= 60) return "#F59E0B";
  return "#EF4444";
}
