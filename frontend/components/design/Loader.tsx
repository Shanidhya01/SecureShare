import { Loader2 } from "lucide-react";
import { cn } from "@/lib/utils";
import { Progress, ProgressLabel } from "@/components/ui/progress";

export function Spinner({ className, size = 16 }: { className?: string; size?: number }) {
  return <Loader2 size={size} className={cn("animate-spin text-muted-foreground", className)} />;
}

/** Inline loading indicator for buttons, cards, and small regions - pairs a spinner with a label. */
export function InlineLoader({ label = "Loading...", className }: { label?: string; className?: string }) {
  return (
    <div className={cn("flex items-center gap-2 text-sm text-muted-foreground", className)}>
      <Spinner size={14} />
      <span>{label}</span>
    </div>
  );
}

/** Determinate progress bar (0-100) built on the shadcn Progress primitive - for scan/upload progress. */
export function ProgressBar({ value, label, className }: { value: number; label?: string; className?: string }) {
  return (
    <Progress value={value} className={className}>
      {label && <ProgressLabel>{label}</ProgressLabel>}
    </Progress>
  );
}
