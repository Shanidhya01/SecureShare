import { AlertCircle, CheckCircle2, Info, TriangleAlert, X, type LucideIcon } from "lucide-react";
import { cn } from "@/lib/utils";

export type AlertTone = "info" | "success" | "warning" | "danger";

const toneConfig: Record<AlertTone, { icon: LucideIcon; classes: string; iconClass: string }> = {
  info: { icon: Info, classes: "bg-primary/10 border-primary/30", iconClass: "text-primary" },
  success: { icon: CheckCircle2, classes: "bg-success/10 border-success/30", iconClass: "text-success" },
  warning: { icon: TriangleAlert, classes: "bg-warning/10 border-warning/30", iconClass: "text-warning" },
  danger: { icon: AlertCircle, classes: "bg-destructive/10 border-destructive/30", iconClass: "text-destructive" },
};

/** Inline, persistent banner for in-page messages (page-level warnings, form errors, empty-config
 *  hints). Distinct from ToasterClient's toasts, which are transient and corner-positioned. */
export default function Alert({
  tone = "info",
  title,
  description,
  action,
  onDismiss,
  className,
}: {
  tone?: AlertTone;
  title: string;
  description?: string;
  action?: React.ReactNode;
  onDismiss?: () => void;
  className?: string;
}) {
  const { icon: Icon, classes, iconClass } = toneConfig[tone];
  return (
    <div role="alert" className={cn("flex items-start gap-3 rounded-xl border p-4", classes, className)}>
      <Icon size={18} className={cn("mt-0.5 shrink-0", iconClass)} />
      <div className="min-w-0 flex-1">
        <p className="text-sm font-medium text-foreground">{title}</p>
        {description && <p className="mt-0.5 text-sm text-muted-foreground">{description}</p>}
        {action && <div className="mt-2">{action}</div>}
      </div>
      {onDismiss && (
        <button
          type="button"
          onClick={onDismiss}
          aria-label="Dismiss"
          className="shrink-0 text-muted-foreground hover:text-foreground"
        >
          <X size={16} />
        </button>
      )}
    </div>
  );
}
