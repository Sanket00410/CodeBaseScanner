# CodeSentinelX User Guide

This guide is written for the actual CodeSentinelX UI.

Use the references below while reading:
- Top bar: `Codebase File or Folder`, `Browse`, `Run Canonical Scan`, scan preset, role selector, `Pause`, `Resume`, `Stop`
- Main tabs: `Code Findings`, `Secure Coding Controls`, `Code Risk Overview`, `Analyzer Catalog`, `Help`
- History area: `Scan History`, `Reports History`, `Audit Logs`
- Report actions: `Open`, `Export`, `Download`, `Select All`, `Delete Selected`, `Delete All`

## 1. Getting Started

### What the app does
- CodeSentinelX scans a local codebase and turns the results into role-aware security reports.
- The app is designed to help developers, security analysts, auditors, and management see different views of the same scan without mixing unrelated data.
- It normalizes findings, groups duplicate alerts, links summary rows to detailed findings, and keeps export history for review.
- In the main app window, the left sidebar helps you move between `Code Risk Overview`, `Secure Coding Controls`, `Code Findings`, `Compliance`, `Scan History`, `Analyzer Catalog`, and `Help`.

### Supported OS/prerequisites
- Windows desktop runtime is the primary supported environment.
- The app needs access to the repository folder you want to scan.
- The codebase may require Node.js and Python tooling depending on the active backend and scanner integrations.
- Make sure you have enough disk space for scan history, exported reports, temporary files, and help/PDF output.

### First scan quick start (3-5 steps)
1. Open the app and go to the main scan page.
2. In the top bar, click `Browse` and select the repository root folder.
3. Choose the role you want to use from the role selector.
4. Choose a scan preset such as `Fast`, `Standard`, or `Deep`.
5. Click `Run Canonical Scan`, wait for the status to complete, and then open the role-relevant report section from the left sidebar. Role changes reuse the same stored scan and redraw the report projection; they do not rerun analyzers.

## 2. Core Concepts

### Roles (Admin, Security Analyst, Developer, Auditor, Management)
- **Admin**: uses the broadest scan and export scope. This view is meant for overall ownership, governance, and full-fidelity review.
- **Security Analyst**: uses a security-heavy workflow focused on triage, validation, and prioritization.
- **Developer**: gets a remediation-first workflow that emphasizes the exact file, line, fix guidance, and verification output.
- **Auditor**: sees compliance and evidence-oriented content, usually with redaction and review focus.
- **Management**: sees the executive view with summary metrics, risk posture, and release-readiness information.
- The role selector in the top bar controls what the app scans, what the backend includes in exports, and what sections appear in the report.

### Scan presets (Fast/Standard/Deep)
- **Fast**: best for quick feedback and repeat development iteration. Use this when you need a fast check before you commit.
- **Standard**: balanced mode. This is the default choice when you want useful coverage without waiting for every deep analyzer.
- **Deep**: highest depth and longest runtime. Use this for major releases, audits, or when you need more confidence and more evidence.
- The preset you choose affects runtime, analyzer depth, and how much evidence the report can collect.

### Report types and who should use each
- **Combined**: the broad report for leadership, admin review, and cross-role visibility.
- **Vulnerability**: the security analysis report for analysts who want grouped issues, severity, and drill-down navigation.
- **Fixes**: the developer report that centers on what to change, validation commands, original code, and fix verification.
- **Existing**: the current-state / control-oriented report used for governance and review workflows.
- **Finding Details**: the detailed drill-down view when you need exact file, line, and evidence context for a specific finding.

## 3. Step-by-Step Workflows

### Run first scan
1. Open the main window.
2. Use `Browse` in the top bar to select the target codebase folder.
3. Pick the role that matches the report you want to generate.
4. Pick the preset that matches how long you can wait.
5. Click `Run Canonical Scan`.
6. Watch the progress/status area until the scan completes.
7. Open `Code Findings` or the matching report area from the left sidebar.
8. If you need the history later, open `Scan History` or `Reports History`.

### Triaging findings
1. Open `Code Risk Overview` or `Code Findings`.
2. Sort by severity, CVSS, or finding count to find the highest-risk items first.
3. Use the search and filters in the report table to narrow the results.
4. Click a grouped alert or linked issue to jump to the detailed finding section.
5. Read the location, recommendation, evidence, and confidence fields before deciding what is actionable.
6. Use the detailed file/line references to move straight to the code that needs attention.

### Exporting reports by role
1. Confirm the role you selected in the top bar.
2. Open the report type that matches the role scope you want.
3. Use the export button in the UI for that report.
4. Choose the format you need, such as HTML, PDF, JSON, or SARIF where available.
5. Open the exported file from the app or from `Reports History`.
6. Use `Select All`, `Delete Selected`, or `Delete All` only after you are sure you do not need those saved export artifacts anymore.

### Verifying fixes
1. Open the `Fixes` report.
2. Read the `Issue Header` first so you know exactly what is being fixed.
3. Check `Primary Location` so you know the full file path and line.
4. Review `What To Change` and the suggested fix before editing code.
5. Run the commands shown in `Validation Commands`.
6. Compare the `Execution Results` and `Fix Verification Status`.
7. If the report says `verified_fixed`, the issue was not reproduced by the configured checks.
8. If it says `still_vulnerable`, the unsafe behavior remained.
9. If it says `inconclusive`, the evidence was not strong enough to prove closure either way.
10. If it says `manual_review_required`, a person must decide because automation could not safely close it.

### Reviewing history and cleanup
1. Open `Scan History` to see prior scan runs.
2. Open `Reports History` to see exported artifacts by role, time, and report type.
3. Open `Audit Logs` when you need to trace actions such as scan start, export, or cleanup.
4. Use the selection checkboxes in `Reports History` to remove old exports without deleting the scan itself.
5. Use `Select All` when you want to clear many old exports at once.

## 4. Tooling & Coverage

### Which scanners are enabled
- The app only enables scanners that are relevant to the repository and allowed by the role policy.
- Analyzer availability is reflected in the `Analyzer Catalog` and in the runtime status shown after a scan.
- If a tool is skipped, it should be because it was not relevant, not because the app forgot to run it.

### Language/ecosystem detection behavior
- The engine looks at the repository stack before running tools.
- A Python project should not run Go-only checks, and a JavaScript project should not depend on unrelated language tools.
- This reduces noise, avoids irrelevant failures, and makes the report more trustworthy.

### Dedup/noise-reduction logic (high-level)
- Findings are normalized by path, title, category, rule ID, and evidence identity.
- Duplicate CVEs and overlapping findings are grouped instead of repeated in every section.
- The report prefers one canonical finding record with evidence from multiple tools instead of many repeated rows.
- Empty or low-value sections should be hidden rather than shown as blank blocks.

## 5. Report Guide

### How to read each report section
- Start with the summary cards and severity distribution to understand the scan at a glance.
- Use the grouped alert section to jump from a summary row into a detailed finding.
- Read the detailed section for exact file path, line, reproduction context, and fix guidance.
- Use the report history and export history to see what was generated, when, and for which role.

### Meaning of severity, confidence, KEV, release gate
- **Severity**: how serious the issue is.
- **Confidence**: how strong the evidence is that the finding is real.
- **CISA KEV / Known Exploited**: whether the issue maps to a known exploited vulnerability source.
- **Release Gate**: whether the issue should block release, be tracked, or be reviewed.
- If a section says something is `N/A`, it usually means that value was not available from the current scan path or that the specific field did not apply.

### How alert grouping + drill-down works
- The alert list groups repeated findings so the report stays readable.
- Clicking an alert takes you to the detailed section for that issue.
- The detailed section shows the exact file or files, the line number, and the evidence behind the alert.
- This helps both developers and reviewers move from summary to code without hunting through the whole report.

### Technical term definitions used in reports
- **verified_fixed**: the fix was tested and the problem no longer reproduced in the configured verification path.
- **still_vulnerable**: the same unsafe behavior was still observed after validation.
- **inconclusive**: the available checks were not strong enough to prove fixed or still vulnerable.
- **manual_review_required**: automated validation could not safely decide the outcome.
- **not_applicable**: the specific check or verification path did not apply to this finding.
- **suppressed**: the finding was intentionally hidden by policy or governance rules.
- **deduplicated**: the same underlying issue was merged into one canonical report entry.

## 6. Troubleshooting

### Common failures (tool not found, timeouts, empty sections)
- A scanner binary or integration may be missing from the local toolchain.
- A tool may time out on a large repository or a deep preset.
- A report section may be empty because the selected role does not need that section.
- A section may also be empty because the scan returned no data that met the report threshold.

### What each error means
- **tool not found**: the analyzer executable or integration could not be launched.
- **timed out**: the analyzer took longer than the configured execution window.
- **query/pack missing**: the tool depends on files or packs that are not present locally.
- **empty section**: the app had no meaningful or role-permitted data to display for that block.

### Exact recovery steps
1. Check the selected role and preset.
2. Verify the repository path is correct.
3. Re-run the scan with a smaller scope or a faster preset if the scan is too slow.
4. Confirm the required toolchain is installed and available.
5. Review the audit log and scan history to see whether the failure was a tool issue or a policy issue.
6. If a report section is empty, confirm whether that is expected for the current role.

## 7. Security & Data Handling

### Local/offline behavior
- CodeSentinelX is designed to analyze local code rather than send the repository somewhere else by default.
- Export files are written to the local exports directory.
- Any network-dependent analyzer behavior depends on the configured tool policy.

### What data is stored (history, exports, audit logs)
- Scan metadata and scan history entries.
- Exported report files such as HTML, PDF, JSON, CSV, XML, SARIF, or patch files when supported.
- Audit log records for scan start, export, open, and cleanup actions.

### Access-control model and role boundaries
- The UI shows actions according to the selected role.
- The backend decides what content can be exported for that role.
- The report should not mix data across roles or expose unrelated findings.
- If a role should not see a section, that section should be removed or reduced instead of showing irrelevant content.

## 8. Performance Tuning

### How to reduce scan time safely
- Use `Fast` for quick checks and `Standard` for normal work.
- Use `Deep` only when you need deeper evidence or release-level review.
- Keep the repository scope tight and avoid scanning unrelated folders.

### Role-scoped scans
- Admin can keep full scope when needed, but non-admin roles should stay narrower to reduce runtime and noise.
- Developer workflows should emphasize fix-relevant output rather than every possible analyzer.
- Management should consume summary-first outputs instead of heavy per-file detail.

### Repo-specific language/tool execution
- Run only the tools that make sense for the repository stack.
- Do not keep language or ecosystem tools active when the repository does not use that language.
- Prefer the primary dependency source for the active stack so the report stays focused and easier to trust.

## 9. FAQ

### Why scan times differ?
- Different roles, presets, languages, and tool depth change the amount of work the app performs.
- A deep scan of a large multi-language repository will take longer than a fast scan of a small one.

### Why some sections are hidden?
- Some blocks are hidden because the current role does not need them, the section is empty, or the data would add noise.
- Hiding low-value sections makes the report easier to read and more useful to the person who opened it.

### Why findings cannot be zero false positives?
- No static analysis workflow can guarantee absolute zero false positives in every codebase.
- The goal is to make findings reproducible, evidence-backed, deduplicated, and easier to verify.
- Stronger validation, better role scope, and tighter tool selection all help reduce noise.

## 10. Versioned Changelog

### What changed per release
- Record what changed in scanning behavior, role scope, report structure, export structure, and validation logic.
- Include notes about new sections, removed sections, or changed evidence flow.
- Include validation notes so you know what was tested before the release shipped.

### Migration notes
- List any required environment updates.
- List any report schema or export-path changes.
- List any role mapping changes.
- List any follow-up checks the operator should run after upgrading.
