import type { StatusTone } from "@/components/design/StatusBadge";

export type Severity = "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

/** Severity -> StatusBadge tone, shared by every SOC/SIEM component (Phase 6). Same role as
 *  StatusBadge's existing riskTone/severityTone maps, but for the SIEM's 5-level scale. */
export const SEVERITY_TONE: Record<Severity, StatusTone> = {
  INFO: "info",
  LOW: "success",
  MEDIUM: "warning",
  HIGH: "warning",
  CRITICAL: "danger",
};

/** Severity -> hex color, for Recharts fills/strokes (same role as analytics/page.tsx's RISK_COLORS). */
export const SEVERITY_COLORS: Record<Severity, string> = {
  INFO: "#38BDF8",
  LOW: "#10B981",
  MEDIUM: "#F59E0B",
  HIGH: "#FB923C",
  CRITICAL: "#EF4444",
};

export const SEVERITY_LEVELS: Severity[] = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"];

export const CATEGORY_LABELS: Record<string, string> = {
  AUTH: "Authentication",
  ENCRYPTION: "Encryption",
  SIGNATURE: "Digital Signatures",
  ZERO_TRUST: "Zero Trust",
  THREAT: "Threat Detection",
  DLP: "Data Loss Prevention",
  UPLOAD: "Upload",
  DOWNLOAD: "Download",
  DEVICE: "Device Management",
  SESSION: "Session Management",
};
