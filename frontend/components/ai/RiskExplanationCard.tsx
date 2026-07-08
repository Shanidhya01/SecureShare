"use client";

import { motion } from "framer-motion";
import { AlertCircle, Gauge, ListTree, Building2, Cpu, Wrench } from "lucide-react";
import { staggerContainer, fadeInUp } from "@/lib/motion";
import StatusBadge, { riskTone } from "@/components/design/StatusBadge";
import type { RiskExplanation } from "@/lib/ai";

/** AI Security Assistant - Feature 4 (AI Risk Explanation). Renders why a risk score/level is
 *  what it is: contributing factors, severity, business/technical impact, and remediation - same
 *  card language as ThreatExplanationCard, distinct schema (RiskExplanation, not ThreatExplanation). */
export default function RiskExplanationCard({ explanation }: { explanation: RiskExplanation }) {
  return (
    <motion.div variants={staggerContainer} initial="hidden" animate="show" className="space-y-4">
      <motion.div variants={fadeInUp} className="flex items-center justify-between rounded-xl border border-border bg-card p-4">
        <div className="flex items-center gap-2">
          <Gauge size={18} className="text-primary" />
          <span className="text-sm font-semibold text-foreground">Risk Severity</span>
        </div>
        <StatusBadge label={explanation.riskSeverity} tone={riskTone[explanation.riskSeverity] ?? "neutral"} />
      </motion.div>

      <motion.div variants={fadeInUp} className="rounded-xl border border-border bg-card p-5">
        <h3 className="flex items-center gap-2 text-sm font-semibold text-foreground mb-2">
          <Gauge size={16} className="text-primary" />
          Why the Score Is High
        </h3>
        <p className="text-sm text-muted-foreground leading-relaxed">{explanation.whyScoreIsHigh}</p>
      </motion.div>

      {explanation.contributingFactors?.length > 0 && (
        <motion.div variants={fadeInUp} className="rounded-xl border border-border bg-card p-5">
          <h3 className="flex items-center gap-2 text-sm font-semibold text-foreground mb-3">
            <ListTree size={16} className="text-warning" />
            Contributing Factors
          </h3>
          <ul className="space-y-2">
            {explanation.contributingFactors.map((factor, i) => (
              <li key={i} className="flex items-start gap-2 text-sm text-muted-foreground">
                <span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-warning" />
                {factor}
              </li>
            ))}
          </ul>
        </motion.div>
      )}

      <motion.div variants={fadeInUp} className="rounded-xl border border-border bg-card p-5">
        <h3 className="flex items-center gap-2 text-sm font-semibold text-foreground mb-2">
          <Building2 size={16} className="text-primary" />
          Business Impact
        </h3>
        <p className="text-sm text-muted-foreground leading-relaxed">{explanation.businessImpact}</p>
      </motion.div>

      <motion.div variants={fadeInUp} className="rounded-xl border border-border bg-card p-5">
        <h3 className="flex items-center gap-2 text-sm font-semibold text-foreground mb-2">
          <Cpu size={16} className="text-primary" />
          Technical Impact
        </h3>
        <p className="text-sm text-muted-foreground leading-relaxed">{explanation.technicalImpact}</p>
      </motion.div>

      {explanation.recommendedRemediation?.length > 0 && (
        <motion.div variants={fadeInUp} className="rounded-xl border border-border bg-card p-5">
          <h3 className="flex items-center gap-2 text-sm font-semibold text-foreground mb-3">
            <Wrench size={16} className="text-success" />
            Recommended Remediation
          </h3>
          <ul className="space-y-2">
            {explanation.recommendedRemediation.map((step, i) => (
              <li key={i} className="flex items-start gap-2 text-sm text-muted-foreground">
                <span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-success" />
                {step}
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
