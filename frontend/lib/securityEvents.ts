import type { StatusTone } from "@/components/design/StatusBadge";

export type SecurityEventType = "new_device" | "device_removed" | "session_revoked" | "download_denied";

export type SecurityEventEntry = {
  id: string;
  type: SecurityEventType;
  message: string;
  filename?: string | null;
  deviceId?: string | null;
  ip?: string | null;
  country?: string | null;
  createdAt: string;
};

export const securityEventTypeLabel: Record<SecurityEventType, string> = {
  new_device: "New Device",
  device_removed: "Device Removed",
  session_revoked: "Session Revoked",
  download_denied: "Download Denied",
};

export const securityEventTypeTone: Record<SecurityEventType, StatusTone> = {
  new_device: "info",
  device_removed: "warning",
  session_revoked: "warning",
  download_denied: "danger",
};
