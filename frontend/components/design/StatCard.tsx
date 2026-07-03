"use client";

import { motion } from "framer-motion";
import type { LucideIcon } from "lucide-react";
import { TrendingDown, TrendingUp } from "lucide-react";
import { fadeInUp } from "@/lib/motion";
import { cn } from "@/lib/utils";

export type StatCardVariant = "primary" | "success" | "warning" | "danger" | "muted" | "purple";

const variantClasses: Record<StatCardVariant, string> = {
  primary: "text-primary bg-primary/10 ring-primary/25",
  success: "text-success bg-success/10 ring-success/25",
  warning: "text-warning bg-warning/10 ring-warning/25",
  danger: "text-destructive bg-destructive/10 ring-destructive/25",
  muted: "text-muted-foreground bg-muted ring-border",
  purple: "text-purple-300 bg-purple-500/10 ring-purple-500/25",
};

export default function StatCard({
  label,
  value,
  icon: Icon,
  variant = "primary",
  delta,
  className,
}: {
  label: string;
  value: React.ReactNode;
  icon: LucideIcon;
  variant?: StatCardVariant;
  delta?: { value: string; direction: "up" | "down"; positive?: boolean };
  className?: string;
}) {
  return (
    <motion.div
      variants={fadeInUp}
      whileHover={{ y: -2 }}
      className={cn(
        "rounded-xl border border-border bg-card p-5 shadow-sm shadow-black/20 transition-colors hover:border-primary/40",
        className
      )}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="text-muted-foreground text-xs font-medium uppercase tracking-wide truncate">{label}</p>
          <p className="mt-2 text-2xl font-bold text-foreground">{value}</p>
          {delta && (
            <p
              className={cn(
                "mt-1 flex items-center gap-1 text-xs font-medium",
                delta.positive === false ? "text-destructive" : "text-success"
              )}
            >
              {delta.direction === "up" ? <TrendingUp size={12} /> : <TrendingDown size={12} />}
              {delta.value}
            </p>
          )}
        </div>
        <div className={cn("inline-flex h-10 w-10 shrink-0 items-center justify-center rounded-lg ring-1", variantClasses[variant])}>
          <Icon size={20} />
        </div>
      </div>
    </motion.div>
  );
}
