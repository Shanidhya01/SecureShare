/**
 * Phase 10 (Compliance & Governance): idempotent seed of the 8 supported frameworks and a
 * representative subset of real, well-known controls per framework (~8-15 each), each mapped to
 * one of the evaluators in controlEvaluators.js. Mirrors services/soar/seedPlaybooks.js's
 * `if (count > 0) return;` guard - only ever seeds once, called from server.js on Mongo connect.
 * This is not an exhaustive published control library; it's enough real, correctly-categorized
 * controls per framework to drive a fully functional assessment engine end-to-end.
 */
import ComplianceFramework from "../../models/ComplianceFramework.js";
import ComplianceControl from "../../models/ComplianceControl.js";

const FRAMEWORKS = [
  { key: "ISO27001", name: "ISO/IEC 27001:2022", description: "Information security management systems", categories: ["Access Control", "Cryptography", "Operations Security", "Incident Management"] },
  { key: "SOC2", name: "SOC 2 Type II", description: "Trust Services Criteria for security, availability, and confidentiality", categories: ["Security", "Availability", "Confidentiality", "Processing Integrity"] },
  { key: "GDPR", name: "General Data Protection Regulation", description: "EU data protection and privacy regulation", categories: ["Data Protection", "Breach Notification", "Access Rights"] },
  { key: "HIPAA", name: "HIPAA Security Rule", description: "US healthcare data protection requirements", categories: ["Access Control", "Audit Controls", "Transmission Security"] },
  { key: "PCIDSS", name: "PCI DSS v4.0", description: "Payment Card Industry Data Security Standard", categories: ["Network Security", "Access Control", "Monitoring", "Vulnerability Management"] },
  { key: "NIST_CSF", name: "NIST Cybersecurity Framework 2.0", description: "Identify, Protect, Detect, Respond, Recover", categories: ["Identify", "Protect", "Detect", "Respond", "Recover"] },
  { key: "CIS", name: "CIS Critical Security Controls v8", description: "Prioritized set of cyber defense best practices", categories: ["Asset Management", "Access Control", "Malware Defense", "Incident Response"] },
  { key: "OWASP_ASVS", name: "OWASP Application Security Verification Standard", description: "Application-layer security verification requirements", categories: ["Authentication", "Session Management", "Data Protection"] }
];

const CONTROLS_BY_FRAMEWORK = {
  ISO27001: [
    { controlId: "A.8.24", title: "Use of Cryptography", category: "Cryptography", severity: "CRITICAL", evaluatorKey: "encryptionEvaluator", recommendation: "Encrypt all files client-side before storage." },
    { controlId: "A.8.5", title: "Secure Authentication", category: "Access Control", severity: "HIGH", evaluatorKey: "mfaEvaluator", recommendation: "Require MFA for all user accounts." },
    { controlId: "A.8.7", title: "Protection Against Malware", category: "Operations Security", severity: "HIGH", evaluatorKey: "malwareProtectionEvaluator", recommendation: "Maintain active malware scanning on all uploads." },
    { controlId: "A.8.16", title: "Monitoring Activities", category: "Operations Security", severity: "MEDIUM", evaluatorKey: "auditLoggingEvaluator", recommendation: "Ensure continuous security event logging." },
    { controlId: "A.8.23", title: "Web Filtering / Data Leakage Prevention", category: "Operations Security", severity: "HIGH", evaluatorKey: "dlpEvaluator", recommendation: "Enforce DLP blocking on sensitive data exfiltration." },
    { controlId: "A.5.15", title: "Access Control Policy", category: "Access Control", severity: "MEDIUM", evaluatorKey: "zeroTrustEvaluator", recommendation: "Enforce zero trust device/network access policy." },
    { controlId: "A.5.24", title: "Incident Management Planning", category: "Incident Management", severity: "HIGH", evaluatorKey: "incidentResponseEvaluator", recommendation: "Ensure incidents are tracked to resolution." },
    { controlId: "A.5.7", title: "Threat Intelligence", category: "Operations Security", severity: "MEDIUM", evaluatorKey: "threatIntelEvaluator", recommendation: "Continuously consume threat intelligence feeds." },
    { controlId: "A.5.17", title: "Authentication Information (Passwords)", category: "Access Control", severity: "HIGH", evaluatorKey: "passwordPolicyEvaluator", recommendation: "Enforce a strong password policy with complexity and expiry." },
    { controlId: "A.5.18", title: "Access Rights Management", category: "Access Control", severity: "MEDIUM", evaluatorKey: "identityEvaluator", recommendation: "Assign and periodically review RBAC roles for every account." },
    { controlId: "A.8.1", title: "User Endpoint Devices", category: "Access Control", severity: "MEDIUM", evaluatorKey: "deviceTrustEvaluator", recommendation: "Maintain a trusted-device inventory and revoke stale devices." }
  ],
  SOC2: [
    { controlId: "CC6.1", title: "Logical Access Controls", category: "Security", severity: "HIGH", evaluatorKey: "mfaEvaluator", recommendation: "Enforce MFA as a logical access control." },
    { controlId: "CC6.7", title: "Data Transmission & Storage Protection", category: "Confidentiality", severity: "CRITICAL", evaluatorKey: "encryptionEvaluator", recommendation: "Encrypt data at rest and in transit." },
    { controlId: "CC6.8", title: "Malicious Software Prevention", category: "Security", severity: "HIGH", evaluatorKey: "malwareProtectionEvaluator", recommendation: "Detect and prevent malicious software." },
    { controlId: "CC7.2", title: "Security Event Monitoring", category: "Security", severity: "MEDIUM", evaluatorKey: "auditLoggingEvaluator", recommendation: "Monitor system components for anomalies." },
    { controlId: "CC7.3", title: "Incident Evaluation & Response", category: "Security", severity: "HIGH", evaluatorKey: "incidentResponseEvaluator", recommendation: "Evaluate and respond to security incidents timely." },
    { controlId: "CC6.6", title: "Boundary Protection", category: "Security", severity: "MEDIUM", evaluatorKey: "zeroTrustEvaluator", recommendation: "Restrict access based on trust signals." },
    { controlId: "CC7.4", title: "Automated Response Procedures", category: "Processing Integrity", severity: "MEDIUM", evaluatorKey: "soarAutomationEvaluator", recommendation: "Automate incident response playbooks." },
    { controlId: "CC6.1-DLP", title: "Data Loss Prevention", category: "Confidentiality", severity: "HIGH", evaluatorKey: "dlpEvaluator", recommendation: "Prevent exfiltration of confidential data." },
    { controlId: "CC6.3", title: "Role-Based Access Provisioning", category: "Security", severity: "MEDIUM", evaluatorKey: "identityEvaluator", recommendation: "Provision access based on assigned roles and review regularly." },
    { controlId: "CC6.1-RISK", title: "Risk-Based Authentication", category: "Security", severity: "MEDIUM", evaluatorKey: "adaptiveAuthEvaluator", recommendation: "Challenge high-risk logins with step-up authentication." }
  ],
  GDPR: [
    { controlId: "Art.32", title: "Security of Processing", category: "Data Protection", severity: "CRITICAL", evaluatorKey: "encryptionEvaluator", recommendation: "Apply encryption as an Article 32 technical measure." },
    { controlId: "Art.32-MFA", title: "Access Control for Processing", category: "Data Protection", severity: "HIGH", evaluatorKey: "mfaEvaluator", recommendation: "Require MFA to protect access to personal data." },
    { controlId: "Art.33", title: "Breach Notification Readiness", category: "Breach Notification", severity: "HIGH", evaluatorKey: "incidentResponseEvaluator", recommendation: "Maintain an incident response process to meet the 72-hour notification window." },
    { controlId: "Art.30", title: "Records of Processing (Audit Trail)", category: "Access Rights", severity: "MEDIUM", evaluatorKey: "auditLoggingEvaluator", recommendation: "Maintain records of processing activities via audit logs." },
    { controlId: "Art.25", title: "Data Protection by Design (DLP)", category: "Data Protection", severity: "HIGH", evaluatorKey: "dlpEvaluator", recommendation: "Prevent unauthorized disclosure of personal data." },
    { controlId: "Art.32-Malware", title: "Resilience Against Malicious Processing", category: "Data Protection", severity: "MEDIUM", evaluatorKey: "malwareProtectionEvaluator", recommendation: "Ensure malware cannot compromise personal data integrity." },
    { controlId: "Art.32-Integrity", title: "Ability to Verify Integrity", category: "Data Protection", severity: "MEDIUM", evaluatorKey: "fileIntegrityEvaluator", recommendation: "Maintain a verifiable integrity hash for stored personal data files." }
  ],
  HIPAA: [
    { controlId: "164.312(a)(1)", title: "Access Control", category: "Access Control", severity: "HIGH", evaluatorKey: "mfaEvaluator", recommendation: "Require unique, MFA-protected user identification." },
    { controlId: "164.312(a)(2)(iv)", title: "Encryption and Decryption", category: "Access Control", severity: "CRITICAL", evaluatorKey: "encryptionEvaluator", recommendation: "Encrypt electronic protected health information." },
    { controlId: "164.312(b)", title: "Audit Controls", category: "Audit Controls", severity: "MEDIUM", evaluatorKey: "auditLoggingEvaluator", recommendation: "Record and examine activity in systems containing PHI." },
    { controlId: "164.312(e)(1)", title: "Transmission Security", category: "Transmission Security", severity: "HIGH", evaluatorKey: "zeroTrustEvaluator", recommendation: "Guard against unauthorized access during transmission." },
    { controlId: "164.308(a)(6)", title: "Security Incident Procedures", category: "Audit Controls", severity: "HIGH", evaluatorKey: "incidentResponseEvaluator", recommendation: "Identify and respond to suspected security incidents." },
    { controlId: "164.308(a)(5)", title: "Malicious Software Protection", category: "Access Control", severity: "MEDIUM", evaluatorKey: "malwareProtectionEvaluator", recommendation: "Protect against malicious software." },
    { controlId: "164.308(a)(5)-PW", title: "Password Management", category: "Access Control", severity: "MEDIUM", evaluatorKey: "passwordPolicyEvaluator", recommendation: "Enforce strong password creation and change procedures." }
  ],
  PCIDSS: [
    { controlId: "3.5", title: "Protect Stored Account Data (Encryption)", category: "Network Security", severity: "CRITICAL", evaluatorKey: "encryptionEvaluator", recommendation: "Render stored account data unreadable via strong cryptography." },
    { controlId: "8.4", title: "Multi-Factor Authentication", category: "Access Control", severity: "HIGH", evaluatorKey: "mfaEvaluator", recommendation: "Enforce MFA for all access to the cardholder data environment." },
    { controlId: "5.2", title: "Anti-Malware Mechanisms", category: "Vulnerability Management", severity: "HIGH", evaluatorKey: "malwareProtectionEvaluator", recommendation: "Deploy anti-malware on all systems commonly affected." },
    { controlId: "10.2", title: "Audit Logs", category: "Monitoring", severity: "MEDIUM", evaluatorKey: "auditLoggingEvaluator", recommendation: "Implement automated audit trails for all system components." },
    { controlId: "7.1", title: "Restrict Access by Business Need", category: "Access Control", severity: "MEDIUM", evaluatorKey: "zeroTrustEvaluator", recommendation: "Limit access to system components by need-to-know." },
    { controlId: "12.10", title: "Incident Response Plan", category: "Monitoring", severity: "HIGH", evaluatorKey: "incidentResponseEvaluator", recommendation: "Maintain and test an incident response plan." },
    { controlId: "11.5", title: "Detect and Respond to Intrusions", category: "Monitoring", severity: "MEDIUM", evaluatorKey: "threatDetectionEvaluator", recommendation: "Deploy intrusion detection/prevention techniques." },
    { controlId: "8.3", title: "Strong Authentication for Users and Administrators", category: "Access Control", severity: "HIGH", evaluatorKey: "passwordPolicyEvaluator", recommendation: "Enforce strong password requirements for all accounts." },
    { controlId: "9.2", title: "Physical/Device Access Controls", category: "Access Control", severity: "MEDIUM", evaluatorKey: "deviceTrustEvaluator", recommendation: "Maintain and review a trusted-device inventory." }
  ],
  NIST_CSF: [
    { controlId: "PR.DS-1", title: "Data-at-Rest Protection", category: "Protect", severity: "CRITICAL", evaluatorKey: "encryptionEvaluator", recommendation: "Protect data-at-rest with encryption." },
    { controlId: "PR.AC-7", title: "Users, Devices Authenticated", category: "Protect", severity: "HIGH", evaluatorKey: "mfaEvaluator", recommendation: "Authenticate users commensurate with risk (MFA)." },
    { controlId: "DE.CM-4", title: "Malicious Code Detection", category: "Detect", severity: "HIGH", evaluatorKey: "malwareProtectionEvaluator", recommendation: "Detect malicious code at entry/exit points." },
    { controlId: "DE.AE-3", title: "Event Data Aggregation", category: "Detect", severity: "MEDIUM", evaluatorKey: "auditLoggingEvaluator", recommendation: "Aggregate event data from multiple sources." },
    { controlId: "PR.AC-3", title: "Remote Access Management", category: "Protect", severity: "MEDIUM", evaluatorKey: "zeroTrustEvaluator", recommendation: "Manage remote access with zero-trust controls." },
    { controlId: "RS.MI-1", title: "Incident Containment", category: "Respond", severity: "HIGH", evaluatorKey: "incidentResponseEvaluator", recommendation: "Contain incidents as they are identified." },
    { controlId: "RS.AN-1", title: "Threat Intelligence Analysis", category: "Respond", severity: "MEDIUM", evaluatorKey: "threatIntelEvaluator", recommendation: "Investigate notifications from detection systems using threat intel." },
    { controlId: "RS.CO-1", title: "Automated Response Coordination", category: "Respond", severity: "MEDIUM", evaluatorKey: "soarAutomationEvaluator", recommendation: "Coordinate response activities via automation." },
    { controlId: "PR.DS-5", title: "Data Leak Protection", category: "Protect", severity: "HIGH", evaluatorKey: "dlpEvaluator", recommendation: "Implement protections against data leaks." },
    { controlId: "PR.AC-1", title: "Identity Governance", category: "Protect", severity: "MEDIUM", evaluatorKey: "identityEvaluator", recommendation: "Manage identities and credentials for authorized devices and users." },
    { controlId: "PR.DS-6", title: "Integrity Checking Mechanisms", category: "Protect", severity: "MEDIUM", evaluatorKey: "fileIntegrityEvaluator", recommendation: "Verify software/firmware/information integrity using checking mechanisms." },
    { controlId: "DE.CM-3", title: "Personnel Activity Monitoring", category: "Detect", severity: "MEDIUM", evaluatorKey: "adaptiveAuthEvaluator", recommendation: "Monitor personnel activity for risk-based authentication events." }
  ],
  CIS: [
    { controlId: "CIS-6.5", title: "Multi-Factor Authentication", category: "Access Control", severity: "HIGH", evaluatorKey: "mfaEvaluator", recommendation: "Require MFA for all accounts." },
    { controlId: "CIS-3.11", title: "Encrypt Sensitive Data at Rest", category: "Access Control", severity: "CRITICAL", evaluatorKey: "encryptionEvaluator", recommendation: "Encrypt sensitive data at rest." },
    { controlId: "CIS-10.1", title: "Malware Defenses", category: "Malware Defense", severity: "HIGH", evaluatorKey: "malwareProtectionEvaluator", recommendation: "Deploy and maintain anti-malware software." },
    { controlId: "CIS-8.2", title: "Audit Log Collection", category: "Asset Management", severity: "MEDIUM", evaluatorKey: "auditLoggingEvaluator", recommendation: "Collect audit logs on all enterprise assets." },
    { controlId: "CIS-17.1", title: "Incident Response Process", category: "Incident Response", severity: "HIGH", evaluatorKey: "incidentResponseEvaluator", recommendation: "Designate personnel and process to manage incidents." },
    { controlId: "CIS-13.1", title: "Network Monitoring & Defense", category: "Access Control", severity: "MEDIUM", evaluatorKey: "zeroTrustEvaluator", recommendation: "Centralize security event alerting across assets." },
    { controlId: "CIS-17.9", title: "Security Incident Response Exercises", category: "Incident Response", severity: "MEDIUM", evaluatorKey: "soarAutomationEvaluator", recommendation: "Automate and regularly exercise incident response." },
    { controlId: "CIS-5.1", title: "Account Inventory & Governance", category: "Access Control", severity: "MEDIUM", evaluatorKey: "identityEvaluator", recommendation: "Maintain and review an inventory of all accounts and roles." },
    { controlId: "CIS-4.1", title: "Secure Configuration of Enterprise Assets", category: "Asset Management", severity: "MEDIUM", evaluatorKey: "deviceTrustEvaluator", recommendation: "Establish and maintain a secure device configuration/trust process." }
  ],
  OWASP_ASVS: [
    { controlId: "V2.1", title: "Password Security & MFA", category: "Authentication", severity: "HIGH", evaluatorKey: "mfaEvaluator", recommendation: "Require multi-factor authentication for verifier." },
    { controlId: "V6.2", title: "Algorithms and Cryptographic Storage", category: "Data Protection", severity: "CRITICAL", evaluatorKey: "encryptionEvaluator", recommendation: "Verify approved cryptographic algorithms are used for storage." },
    { controlId: "V3.2", title: "Session Binding", category: "Session Management", severity: "MEDIUM", evaluatorKey: "sessionManagementEvaluator", recommendation: "Enforce session timeout and concurrent session limits." },
    { controlId: "V7.1", title: "Log Content Requirements", category: "Data Protection", severity: "MEDIUM", evaluatorKey: "auditLoggingEvaluator", recommendation: "Ensure security-relevant events are logged." },
    { controlId: "V13.2", title: "File Upload Restrictions", category: "Data Protection", severity: "HIGH", evaluatorKey: "malwareProtectionEvaluator", recommendation: "Verify uploaded files are scanned for malware." },
    { controlId: "V8.3", title: "Sensitive Private Data Handling", category: "Data Protection", severity: "HIGH", evaluatorKey: "dlpEvaluator", recommendation: "Prevent sensitive data from being sent to unauthorized parties." },
    { controlId: "V2.1-PW", title: "Password Security Requirements", category: "Authentication", severity: "HIGH", evaluatorKey: "passwordPolicyEvaluator", recommendation: "Enforce minimum length and complexity for all passwords." },
    { controlId: "V2.2", title: "General Authenticator Security (Risk-Based)", category: "Authentication", severity: "MEDIUM", evaluatorKey: "adaptiveAuthEvaluator", recommendation: "Apply risk-based/step-up authentication for anomalous logins." },
    { controlId: "V6.1", title: "Data Classification & Integrity", category: "Data Protection", severity: "MEDIUM", evaluatorKey: "fileIntegrityEvaluator", recommendation: "Verify the integrity of stored data using cryptographic hashes." },
    { controlId: "V6.3", title: "Digital Signature Verification", category: "Data Protection", severity: "MEDIUM", evaluatorKey: "digitalSignatureEvaluator", recommendation: "Digitally sign and verify sensitive data artifacts." }
  ]
};

export async function ensureSeedFrameworks() {
  const count = await ComplianceFramework.countDocuments();
  if (count === 0) {
    const inserted = await ComplianceFramework.insertMany(FRAMEWORKS);
    const byKey = Object.fromEntries(inserted.map((f) => [f.key, f]));

    const controlDocs = [];
    for (const [frameworkKey, controls] of Object.entries(CONTROLS_BY_FRAMEWORK)) {
      const framework = byKey[frameworkKey];
      if (!framework) continue;
      for (const control of controls) {
        controlDocs.push({ ...control, framework: framework._id });
      }
    }

    await ComplianceControl.insertMany(controlDocs);
    return;
  }

  // Frameworks already seeded (e.g. from an earlier deploy of this phase) - top up any controls
  // added since then (by unique framework+controlId) without touching what's already there or
  // re-running the full seed. Keeps this function safe to call on every server start.
  await ensureAdditionalControls();
}

async function ensureAdditionalControls() {
  const frameworks = await ComplianceFramework.find().lean();
  const byKey = Object.fromEntries(frameworks.map((f) => [f.key, f]));

  for (const [frameworkKey, controls] of Object.entries(CONTROLS_BY_FRAMEWORK)) {
    const framework = byKey[frameworkKey];
    if (!framework) continue;
    for (const control of controls) {
      await ComplianceControl.updateOne(
        { framework: framework._id, controlId: control.controlId },
        { $setOnInsert: { ...control, framework: framework._id } },
        { upsert: true }
      );
    }
  }
}
