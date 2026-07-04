import mongoose from "mongoose";

/**
 * Phase 10 (Compliance & Governance): a single control within a ComplianceFramework (e.g. ISO
 * 27001 A.9.2.1, GDPR Art.32). `evaluatorKey` names the pure function in
 * services/compliance/controlEvaluators.js that judges this control - many controls across
 * different frameworks share the same evaluator (e.g. both ISO A.9 and NIST PR.AC map to
 * `mfaEvaluator`), matching real-world control-overlap between frameworks.
 */
const complianceControlSchema = new mongoose.Schema(
  {
    framework: { type: mongoose.Schema.Types.ObjectId, ref: "ComplianceFramework", required: true },
    controlId: { type: String, required: true },
    title: { type: String, required: true },
    description: String,
    category: { type: String, required: true },
    severity: { type: String, enum: ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"], default: "MEDIUM" },
    evaluatorKey: {
      type: String,
      required: true,
      enum: [
        "encryptionEvaluator", "mfaEvaluator", "threatDetectionEvaluator", "malwareProtectionEvaluator",
        "dlpEvaluator", "zeroTrustEvaluator", "auditLoggingEvaluator", "sessionManagementEvaluator",
        "incidentResponseEvaluator", "threatIntelEvaluator", "soarAutomationEvaluator",
        // Phase 10 continuation: password policy, identity governance, device trust, adaptive
        // auth, digital signatures, and file integrity - see controlEvaluators.js.
        "passwordPolicyEvaluator", "identityEvaluator", "deviceTrustEvaluator", "adaptiveAuthEvaluator",
        "digitalSignatureEvaluator", "fileIntegrityEvaluator",
        // Phase 11 (CSPM/ASM): cloud security posture findings feed into compliance scoring.
        "cloudSecurityEvaluator",
        // Phase 12 (DevSecOps/Supply Chain): dependency/secret/SAST/container/IaC findings.
        "devSecOpsEvaluator"
      ]
    },
    recommendation: String,
    owner: { type: mongoose.Schema.Types.ObjectId, ref: "User", default: null }
  },
  { timestamps: true }
);

complianceControlSchema.index({ framework: 1, controlId: 1 }, { unique: true });
complianceControlSchema.index({ category: 1 });

export default mongoose.model("ComplianceControl", complianceControlSchema);
