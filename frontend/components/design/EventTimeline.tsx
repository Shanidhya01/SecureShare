"use client";

import { motion } from "framer-motion";
import type { LucideIcon } from "lucide-react";
import { cn } from "@/lib/utils";
import { staggerContainer, fadeInUp } from "@/lib/motion";
import StatusBadge, { type StatusTone } from "@/components/design/StatusBadge";

export type EventTimelineItem = {
  key: string;
  icon: LucideIcon;
  title: string;
  description?: string;
  timestamp: string | Date;
  tone?: StatusTone;
  badgeLabel?: string;
};

const toneRingClass: Record<StatusTone, string> = {
  neutral: "bg-muted text-muted-foreground ring-border",
  success: "bg-success/15 text-success ring-success/40",
  warning: "bg-warning/15 text-warning ring-warning/40",
  danger: "bg-destructive/15 text-destructive ring-destructive/40",
  info: "bg-primary/15 text-primary ring-primary/40",
};

/** Chronological event list with a connecting line - used anywhere the app shows a history of
 *  discrete past events (Security Timeline, Threat Timeline, File Access history), as opposed to
 *  ProgressTimeline's step-by-step in-flight state machine. */
export default function EventTimeline({
  items,
  emptyLabel = "No activity yet.",
  className,
}: {
  items: EventTimelineItem[];
  emptyLabel?: string;
  className?: string;
}) {
  if (items.length === 0) {
    return <p className="text-sm text-muted-foreground py-6 text-center">{emptyLabel}</p>;
  }

  return (
    <motion.ol variants={staggerContainer} initial="hidden" animate="show" className={cn("space-y-0", className)}>
      {items.map((item, idx) => {
        const isLast = idx === items.length - 1;
        const tone = item.tone ?? "neutral";
        const Icon = item.icon;
        return (
          <motion.li key={item.key} variants={fadeInUp} className="relative flex gap-3 pb-5 last:pb-0">
            {!isLast && <span className="absolute left-[15px] top-8 h-[calc(100%-1.25rem)] w-px bg-border" />}
            <span className={cn("relative z-10 flex h-8 w-8 shrink-0 items-center justify-center rounded-full ring-1", toneRingClass[tone])}>
              <Icon size={15} />
            </span>
            <div className="min-w-0 pt-1 flex-1">
              <div className="flex items-start justify-between gap-2">
                <p className="text-sm font-medium text-foreground truncate">{item.title}</p>
                {item.badgeLabel && <StatusBadge label={item.badgeLabel} tone={tone} className="shrink-0" />}
              </div>
              {item.description && <p className="text-xs text-muted-foreground mt-0.5">{item.description}</p>}
              <p className="text-[11px] text-muted-foreground/70 mt-1">{new Date(item.timestamp).toLocaleString()}</p>
            </div>
          </motion.li>
        );
      })}
    </motion.ol>
  );
}
