# CodeSentinelX User Guide

## 1. Getting Started

### What the app does
- CodeSentinelX performs codebase security analysis with role-scoped scan behavior and role-scoped exports.
- It normalizes findings, deduplicates repeated results, maps risk to CWE/OWASP, and presents outputs for different audiences (engineering, AppSec, audit, management).
- It supports end-to-end workflow: scan, triage, fix review, export, evidence tracking, and report history management.

### Supported OS/prerequisites
- Windows desktop runtime (Electron app) is the primary supported operator environment.
- Node.js and Python runtimes are required by the project for frontend/backend orchestration and scanner execution.
- Local filesystem access to the target repository is required.
- Sufficient disk space is required for exports, history, and temporary scan artifacts.

### First scan quick start (3-5 steps)
1. Launch the app and select the target repository folder.
2. Choose role and scan preset.
3. Click **Run Scan** and wait for completion status.
4. Review findings in Code Findings and role-relevant dashboard sections.
5. Export the role-appropriate report (HTML/PDF/JSON/etc. per role policy).

## 2. Core Concepts

### Roles (Admin, Security Analyst, Developer, Auditor, Management)
- **Admin**: full scope governance and operational visibility.
- **Security Analyst**: triage, validation, risk operations, and security analysis outputs.
- **Developer**: remediation-focused workflow and fix-first outputs.
- **Auditor**: compliance/review scope with controlled evidence exposure.
- **Management**: executive summary and risk posture consumption.

### Scan presets (Fast/Standard/Deep)
- **Fast**: reduced time, focused signal, useful for rapid iteration.
- **Standard**: balanced depth and runtime for regular secure coding operations.
- **Deep**: maximum analysis depth and evidence collection for high-assurance review.

### Report types and who should use each
- **Combined**: broad role-scoped report for Admin/Management contexts.
- **Vulnerability**: security-analysis heavy report for Security Analyst workflows.
- **Fixes**: remediation-first report for Developer workflows.
- **Existing**: control/compliance-oriented report for Auditor review contexts.
- **Finding Details**: granular finding table for targeted review workflows.

## 3. Step-by-Step Workflows

### Run first scan
1. Open app.
2. Browse and select repository root.
3. Select role and preset.
4. Start scan and monitor progress messages.
5. Open generated scan record from history when complete.

### Triaging findings
1. Sort findings by severity/CVSS.
2. Filter by CWE/OWASP/module/file.
3. Open grouped alerts and drill down into detailed finding sections.
4. Validate evidence context (file/line/tool/source).
5. Mark reviewed findings where workflow supports review-state updates.

### Exporting reports by role
1. Keep selected UI role aligned with scan role.
2. Use export preset shown for that role.
3. Choose allowed format (role policy enforced by backend).
4. Open exported file directly from app or Reports History.

### Verifying fixes
1. Review remediation guidance and validation sections in Fixes report.
2. Compare original code, suggested fix, and validation evidence.
3. Use post-fix output and verification status to decide closure vs rework.
4. Re-scan after code updates for confirmation.

### Reviewing history and cleanup
1. Use Scan History for prior scan runs.
2. Use Audit Logs for action traceability.
3. Use Reports History for exported artifacts by role/time.
4. Use selection controls to delete selected/all report files when cleanup is required.

## 4. Tooling & Coverage

### Which scanners are enabled
- Scanner availability is controlled by platform policy, role scope, and repository relevance.
- Enabled/selected tools are visible in analyzer/catalog and reflected in scan outputs.
- Some tools can be intentionally skipped when irrelevant to repo stack or policy.

### Language/ecosystem detection behavior
- The engine detects repository languages/ecosystems and limits execution to relevant analyzer families.
- Stack mismatch tools are skipped to reduce noise and avoid irrelevant failures.
- Dependency analysis is ecosystem-aware and consolidated during normalization/dedup.

### Dedup/noise-reduction logic (high-level)
- Canonical path/title/category normalization is applied.
- Similar findings are deduplicated by normalized identity and evidence strategy.
- Overlapping tool outputs are merged where appropriate to prevent report bloat.
- Role and section filters suppress low-value/empty blocks in role-specific outputs.

## 5. Report Guide

### How to read each report section
- Start with summary cards, severity distribution, and top prioritized findings.
- Use Alerts by Type for grouped navigation.
- Open detailed sections for exact file/line/evidence/recommendations.
- Use runtime/data-quality sections to assess scan reliability.

### Meaning of severity, confidence, KEV, release gate
- **Severity**: impact/urgency tier (Critical, High, Medium, Low, Info).
- **Confidence**: certainty level of finding evidence quality and corroboration.
- **CISA KEV / Known Exploited**: findings tied to known exploited vulnerability intelligence.
- **Release Gate**: operational decision state (for example, block/fix-before-prod/track).

### How alert grouping + drill-down works
- Alerts are grouped to reduce repetition and report bulk.
- Clicking grouped alerts navigates to detailed sections.
- Detailed sections contain deeper evidence, taxonomy mapping, and location context.

### Technical term definitions used in reports
- **verified_fixed**: remediation verification indicates issue no longer reproduced under configured checks.
- **still_vulnerable**: verification indicates vulnerable behavior remains.
- **inconclusive**: available evidence was insufficient to prove fixed or vulnerable conclusively.
- **manual_review_required**: automatic checks cannot safely decide closure; analyst/developer review needed.
- **not_applicable**: validation path not applicable for the specific finding family/context.
- **suppressed**: finding intentionally excluded by policy with governance trail.
- **deduplicated**: repeated equivalent findings merged into a canonical record.

## 6. Troubleshooting

### Common failures (tool not found, timeouts, empty sections)
- Tool unavailable or not executable.
- Network-restricted or policy-restricted tool behavior.
- Timeout on heavy analyzers for large repositories.
- Empty report section due to role scope, no applicable data, or filtered output.

### What each error means
- **tool not found**: analyzer binary/integration unavailable in runtime.
- **timed out**: analyzer exceeded configured execution window.
- **query/pack missing**: tool-specific assets not present (for example query packs).
- **empty section**: no role-permitted or meaningful data for that block.

### Exact recovery steps
1. Confirm selected role and scan preset.
2. Confirm repository path and stack relevance.
3. Re-run with suitable preset or smaller scope if runtime is excessive.
4. Verify analyzer/tool prerequisites and policy settings.
5. Re-check exports and audit logs for execution evidence and failures.

## 7. Security & Data Handling

### Local/offline behavior
- App is designed for local codebase processing with role-scoped outputs.
- Network/tool behavior depends on policy configuration and enabled integrations.
- Exported artifacts are generated locally in the configured exports directory.

### What data is stored (history, exports, audit logs)
- Scan history records (metadata and report references).
- Exported report files (HTML/PDF/JSON/etc.).
- Audit logs for actions (scan/export/review/cleanup).

### Access-control model and role boundaries
- UI presents role-specific operations.
- Backend enforces role-to-report and role-to-format restrictions.
- Role mismatch between loaded scan and selected export is blocked.
- Data exposure is constrained by section/scope policies per role.

## 8. Performance Tuning

### How to reduce scan time safely
- Choose Fast/Standard presets appropriately.
- Avoid running deep scans for every iteration.
- Keep repo scope precise and avoid unrelated directories.

### Role-scoped scans
- Role-scoped execution reduces unnecessary analysis paths.
- Report output is role-filtered to reduce noise and improve relevance.

### Repo-specific language/tool execution
- Execute only analyzers relevant to detected repository languages.
- Prefer primary dependency source where policy defines one.
- Keep heavyweight analyzers for deep/admin workflows when required.

## 9. FAQ

### “Why scan times differ?”
- Different roles/presets/tool scopes execute different analysis depth.
- Repository size/language mix/tool runtime contributes to variation.

### “Why some sections are hidden?”
- Role policy, section gating, and empty/low-value suppression remove non-actionable blocks.

### “Why findings can’t be zero false positives?”
- Static and hybrid analysis can reduce noise substantially but cannot guarantee absolute zero false positives in all code contexts.
- Goal is measurable confidence, reproducibility, and governance-backed suppression workflow.

## 10. Versioned Changelog

### What changed per release
- Track scanner logic updates, report UX changes, role policy updates, and tool integration changes by version/date.
- Record backward-impact notes and validation coverage for each release.

### Migration notes
- Include required config/env changes.
- Include report schema compatibility notes.
- Include any role mapping or export policy changes.
- Include post-upgrade verification checklist (scan, export, review, cleanup).
