"use client";

import { motion } from "framer-motion";
import { Check, Loader2, X } from "lucide-react";
import { cn } from "@/lib/utils";

export type TimelineStepState = "pending" | "active" | "done" | "error" | "skipped";

export type TimelineStep = {
  key: string;
  label: string;
  state: TimelineStepState;
  detail?: string;
};

/** Vertical step list used by Upload (scan/DLP/encrypt/sign/upload) and Download
 *  (policy/signature/threat/decrypt) flows - purely presentational, driven by whatever
 *  state machine the page already runs. */
export default function ProgressTimeline({ steps }: { steps: TimelineStep[] }) {
  return (
    <ol className="space-y-0">
      {steps.map((step, idx) => {
        const isLast = idx === steps.length - 1;
        return (
          <li key={step.key} className="relative flex gap-3 pb-6 last:pb-0">
            {!isLast && (
              <span
                className={cn(
                  "absolute left-[15px] top-8 h-[calc(100%-1.5rem)] w-px",
                  step.state === "done" ? "bg-success/50" : "bg-border"
                )}
              />
            )}
            <StepIcon state={step.state} />
            <div className="min-w-0 pt-1">
              <p
                className={cn(
                  "text-sm font-semibold",
                  step.state === "pending" ? "text-muted-foreground" : "text-foreground"
                )}
              >
                {step.label}
              </p>
              {step.detail && <p className="text-xs text-muted-foreground mt-0.5">{step.detail}</p>}
            </div>
          </li>
        );
      })}
    </ol>
  );
}

function StepIcon({ state }: { state: TimelineStepState }) {
  const base = "relative z-10 flex h-8 w-8 shrink-0 items-center justify-center rounded-full ring-1";
  if (state === "done") {
    return (
      <span className={cn(base, "bg-success/15 text-success ring-success/40")}>
        <Check size={16} />
      </span>
    );
  }
  if (state === "active") {
    return (
      <motion.span
        className={cn(base, "bg-primary/15 text-primary ring-primary/40")}
        animate={{ scale: [1, 1.08, 1] }}
        transition={{ repeat: Infinity, duration: 1.4 }}
      >
        <Loader2 size={16} className="animate-spin" />
      </motion.span>
    );
  }
  if (state === "error") {
    return (
      <span className={cn(base, "bg-destructive/15 text-destructive ring-destructive/40")}>
        <X size={16} />
      </span>
    );
  }
  return <span className={cn(base, "bg-muted text-muted-foreground ring-border")} />;
}
