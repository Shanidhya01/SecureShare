"use client";

import { motion } from "framer-motion";
import type { LucideIcon } from "lucide-react";
import { fadeInUp } from "@/lib/motion";
import { buttonVariants } from "@/components/ui/button";
import { cn } from "@/lib/utils";

export default function EmptyState({
  icon: Icon,
  title,
  description,
  actionLabel,
  onAction,
  actionHref,
}: {
  icon: LucideIcon;
  title: string;
  description?: string;
  actionLabel?: string;
  onAction?: () => void;
  actionHref?: string;
}) {
  return (
    <motion.div
      variants={fadeInUp}
      initial="hidden"
      animate="show"
      className="flex flex-col items-center justify-center rounded-2xl border border-dashed border-border bg-card/60 px-6 py-16 text-center"
    >
      <div className="mb-4 inline-flex h-14 w-14 items-center justify-center rounded-2xl bg-muted text-muted-foreground ring-1 ring-border">
        <Icon size={26} />
      </div>
      <h2 className="text-lg font-semibold text-foreground">{title}</h2>
      {description && <p className="mt-2 max-w-md text-sm text-muted-foreground">{description}</p>}
      {actionLabel && actionHref && (
        <a href={actionHref} className={cn(buttonVariants({ size: "lg" }), "mt-5")}>
          {actionLabel}
        </a>
      )}
      {actionLabel && !actionHref && onAction && (
        <button type="button" onClick={onAction} className={cn(buttonVariants({ size: "lg" }), "mt-5")}>
          {actionLabel}
        </button>
      )}
    </motion.div>
  );
}
