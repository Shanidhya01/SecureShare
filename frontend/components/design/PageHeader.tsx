"use client";

import { motion } from "framer-motion";
import type { LucideIcon } from "lucide-react";
import { fadeInUp } from "@/lib/motion";
import { cn } from "@/lib/utils";

export default function PageHeader({
  icon: Icon,
  title,
  description,
  accent = "primary",
  actions,
  className,
}: {
  icon: LucideIcon;
  title: string;
  description?: string;
  accent?: "primary" | "danger" | "warning" | "success" | "purple";
  actions?: React.ReactNode;
  className?: string;
}) {
  const accentClasses: Record<string, { chip: string; gradient: string }> = {
    primary: { chip: "bg-primary/10 text-primary ring-primary/30", gradient: "from-primary to-cyan-400" },
    danger: { chip: "bg-destructive/10 text-destructive ring-destructive/30", gradient: "from-red-400 to-orange-400" },
    warning: { chip: "bg-warning/10 text-warning ring-warning/30", gradient: "from-amber-400 to-orange-400" },
    success: { chip: "bg-success/10 text-success ring-success/30", gradient: "from-emerald-400 to-teal-400" },
    purple: { chip: "bg-purple-500/10 text-purple-300 ring-purple-500/30", gradient: "from-purple-400 to-pink-400" },
  };
  const { chip: chipClass, gradient: gradientClass } = accentClasses[accent];

  return (
    <motion.div
      variants={fadeInUp}
      initial="hidden"
      animate="show"
      className={cn(
        "mb-8 flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between",
        className
      )}
    >
      <div className="flex items-center gap-3">
        <div
          className={cn(
            "inline-flex h-11 w-11 shrink-0 items-center justify-center rounded-xl ring-1",
            chipClass
          )}
        >
          <Icon size={22} />
        </div>
        <div>
          <h1
            className={cn(
              "text-2xl sm:text-3xl font-black text-transparent bg-clip-text bg-linear-to-r",
              gradientClass
            )}
          >
            {title}
          </h1>
          {description && <p className="text-muted-foreground text-sm mt-0.5">{description}</p>}
        </div>
      </div>
      {actions && <div className="flex items-center gap-2 shrink-0">{actions}</div>}
    </motion.div>
  );
}
