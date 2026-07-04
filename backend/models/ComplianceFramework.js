import mongoose from "mongoose";

/**
 * Phase 10 (Compliance & Governance): one of the 8 supported compliance/regulatory frameworks.
 * Each framework owns a set of ComplianceControl docs. Seeded once (idempotently) by
 * services/compliance/seedFrameworks.js - never created via a public API.
 */
const complianceFrameworkSchema = new mongoose.Schema(
  {
    key: {
      type: String,
      required: true,
      unique: true,
      enum: ["ISO27001", "SOC2", "GDPR", "HIPAA", "PCIDSS", "NIST_CSF", "CIS", "OWASP_ASVS"]
    },
    name: { type: String, required: true },
    description: String,
    categories: { type: [String], default: [] },
    enabled: { type: Boolean, default: true }
  },
  { timestamps: true }
);

export default mongoose.model("ComplianceFramework", complianceFrameworkSchema);
