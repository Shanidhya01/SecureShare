import { cn } from "@/lib/utils";

export type StatusTone = "neutral" | "success" | "warning" | "danger" | "info";

const toneClasses: Record<StatusTone, string> = {
  neutral: "text-muted-foreground bg-muted ring-border",
  success: "text-success bg-success/10 ring-success/30",
  warning: "text-warning bg-warning/10 ring-warning/30",
  danger: "text-destructive bg-destructive/10 ring-destructive/30",
  info: "text-primary bg-primary/10 ring-primary/30",
};

/** Generic pill badge used for risk levels, DLP severities/decisions, encryption/signature/threat
 *  status, and any other short status label - pass the semantic `tone` and it handles the rest. */
export default function StatusBadge({
  label,
  tone = "neutral",
  className,
}: {
  label: string;
  tone?: StatusTone;
  className?: string;
}) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-full px-2 py-0.5 text-[10px] font-bold uppercase tracking-wide ring-1 whitespace-nowrap",
        toneClasses[tone],
        className
      )}
    >
      {label}
    </span>
  );
}

export const riskTone: Record<string, StatusTone> = {
  Low: "success",
  Medium: "warning",
  High: "warning",
  Critical: "danger",
};

export const severityTone: Record<string, StatusTone> = {
  None: "neutral",
  Low: "success",
  Medium: "warning",
  High: "warning",
  Critical: "danger",
};

export const decisionTone: Record<string, StatusTone> = {
  allow: "success",
  warn: "warning",
  require_approval: "warning",
  block: "danger",
};
