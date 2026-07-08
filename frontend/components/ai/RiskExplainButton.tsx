"use client";

import { useState } from "react";
import { Gauge, Loader2, AlertCircle } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from "@/components/ui/dialog";
import RiskExplanationCard from "@/components/ai/RiskExplanationCard";
import { explainRisk, type SourceType, type RiskExplanation } from "@/lib/ai";
import { apiErrorMessage } from "@/lib/errors";

/** AI Security Assistant - Feature 4 (AI Risk Explanation). "Explain" trigger for any risk score/
 *  level display (e.g. a file's numeric threat score). Same dialog pattern as
 *  ExplainWithAIButton, distinct endpoint/schema (RiskExplanation, not ThreatExplanation) since
 *  the question being answered is "why is this score what it is," not "what happened." */
export default function RiskExplainButton({ sourceType, sourceId }: { sourceType: SourceType; sourceId: string }) {
  const [open, setOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  const [explanation, setExplanation] = useState<RiskExplanation | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const handleClick = async () => {
    setOpen(true);
    if (explanation || notice) return;

    const token = localStorage.getItem("token");
    if (!token) return;

    setLoading(true);
    try {
      const res = await explainRisk(sourceType, sourceId, token);
      if (res.status === "ok") {
        setExplanation(res.explanation);
      } else {
        setNotice(res.message);
      }
    } catch (err: unknown) {
      setNotice(apiErrorMessage(err, "AI risk explanation failed. Try again later."));
    } finally {
      setLoading(false);
    }
  };

  const handleOpenChange = (next: boolean) => {
    setOpen(next);
    if (!next) {
      setExplanation(null);
      setNotice(null);
    }
  };

  return (
    <>
      <Button type="button" variant="outline" size="sm" onClick={handleClick} className="gap-1.5">
        <Gauge size={14} className="text-primary" />
        Explain
      </Button>
      <Dialog open={open} onOpenChange={handleOpenChange}>
        <DialogContent className="sm:max-w-xl max-h-[85vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Gauge size={16} className="text-primary" />
              AI Risk Explanation
            </DialogTitle>
            <DialogDescription>Why this risk score is what it is, generated from this file&apos;s real scan data.</DialogDescription>
          </DialogHeader>

          {loading && (
            <div className="flex items-center justify-center gap-2 py-12 text-muted-foreground text-sm">
              <Loader2 size={16} className="animate-spin" />
              Asking the AI Security Assistant...
            </div>
          )}

          {!loading && notice && (
            <div className="p-4 bg-muted border border-border rounded-lg flex items-start gap-2">
              <AlertCircle className="text-muted-foreground shrink-0 mt-0.5" size={16} />
              <p className="text-muted-foreground text-sm">{notice}</p>
            </div>
          )}

          {!loading && explanation && <RiskExplanationCard explanation={explanation} />}
        </DialogContent>
      </Dialog>
    </>
  );
}
