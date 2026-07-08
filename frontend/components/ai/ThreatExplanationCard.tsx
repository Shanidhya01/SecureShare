"use client";

import { motion } from "framer-motion";
import { AlertCircle, ShieldQuestion, Gauge, Building2, Cpu, ListChecks, Lightbulb, Info, FileSpreadsheet } from "lucide-react";
import { staggerContainer, fadeInUp } from "@/lib/motion";
import StatusBadge, { riskTone } from "@/components/design/StatusBadge";
import type { ThreatExplanation } from "@/lib/ai";

/** AI Security Assistant - Feature 2 (AI Threat Explanation). Renders a structured Gemini threat
 *  explanation as a grid of design-system-consistent cards (same rounded-xl/border-border/bg-card
 *  language as every other panel in this app): executive summary, what happened, why detected,
 *  business impact, technical impact, risk level, recommended actions, prevention tips, plus an
 *  explicit "Assumptions" callout when the model flagged missing data (the concrete UI side of
 *  "do not hallucinate"). */
export default function ThreatExplanationCard({ explanation }: { explanation: ThreatExplanation }) {
  const sections = [
    { key: "executiveSummary", title: "Executive Summary", icon: FileSpreadsheet, body: explanation.executiveSummary },
    { key: "whatHappened", title: "What Happened?", icon: Info, body: explanation.whatHappened },
    { key: "whyDetected", title: "Why Was It Detected?", icon: ShieldQuestion, body: explanation.whyDetected },
    { key: "businessImpact", title: "Business Impact", icon: Building2, body: explanation.businessImpact },
    { key: "technicalImpact", title: "Technical Impact", icon: Cpu, body: explanation.technicalImpact },
  ] as const;

  return (
    <motion.div variants={staggerContainer} initial="hidden" animate="show" className="space-y-4">
      <motion.div variants={fadeInUp} className="flex items-center justify-between rounded-xl border border-border bg-card p-4">
        <div className="flex items-center gap-2">
          <Gauge size={18} className="text-primary" />
          <span className="text-sm font-semibold text-foreground">Risk Level</span>
        </div>
        <StatusBadge label={explanation.riskLevel} tone={riskTone[explanation.riskLevel] ?? "neutral"} />
      </motion.div>

      {sections.map((s) => (
        <motion.div key={s.key} variants={fadeInUp} className="rounded-xl border border-border bg-card p-5">
          <h3 className="flex items-center gap-2 text-sm font-semibold text-foreground mb-2">
            <s.icon size={16} className="text-primary" />
            {s.title}
          </h3>
          <p className="text-sm text-muted-foreground leading-relaxed">{s.body}</p>
        </motion.div>
      ))}

      {explanation.recommendedActions?.length > 0 && (
        <motion.div variants={fadeInUp} className="rounded-xl border border-border bg-card p-5">
          <h3 className="flex items-center gap-2 text-sm font-semibold text-foreground mb-3">
            <ListChecks size={16} className="text-success" />
            Recommended Actions
          </h3>
          <ul className="space-y-2">
            {explanation.recommendedActions.map((action, i) => (
              <li key={i} className="flex items-start gap-2 text-sm text-muted-foreground">
                <span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-success" />
                {action}
              </li>
            ))}
          </ul>
        </motion.div>
      )}

      {explanation.preventionTips?.length > 0 && (
        <motion.div variants={fadeInUp} className="rounded-xl border border-border bg-card p-5">
          <h3 className="flex items-center gap-2 text-sm font-semibold text-foreground mb-3">
            <Lightbulb size={16} className="text-warning" />
            Prevention Tips
          </h3>
          <ul className="space-y-2">
            {explanation.preventionTips.map((tip, i) => (
              <li key={i} className="flex items-start gap-2 text-sm text-muted-foreground">
                <span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-warning" />
                {tip}
              </li>
            ))}
          </ul>
        </motion.div>
      )}

      {explanation.assumptions?.length > 0 && (
        <motion.div variants={fadeInUp} className="p-4 bg-warning/10 border border-warning/30 rounded-lg flex items-start gap-2">
          <AlertCircle className="text-warning shrink-0 mt-0.5" size={16} />
          <div className="min-w-0">
            <p className="text-warning text-xs font-semibold mb-1">Assumptions &amp; Missing Data</p>
            <ul className="space-y-1">
              {explanation.assumptions.map((a, i) => (
                <li key={i} className="text-warning/90 text-xs">{a}</li>
              ))}
            </ul>
          </div>
        </motion.div>
      )}
    </motion.div>
  );
}
