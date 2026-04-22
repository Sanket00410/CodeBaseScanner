# One Scan, Many Role Reports Implementation Plan

1. Define the canonical scan object first.
Create one source-of-truth scan model that holds the complete result of a single scan run: target path, target type, preset, timestamps, tool execution status, raw findings, deduplicated findings, severity distribution, CWE/OWASP/CVE data, evidence, verification, and summary metrics. This becomes the only scan payload the UI and exports should read from.

2. Stop treating role selection as a scan trigger.
Right now the role often behaves like it changes the scan. Replace that with a projection model: the scan runs once, and the selected role only changes what slice of the canonical scan is shown. Admin, Security Analyst, Developer, Auditor, and Management should all read from the same stored scan result.

3. Separate scan execution from report rendering in the backend.
Keep the scan engine responsible only for running tools, collecting findings, and building the canonical report payload. Move role-specific hiding, redaction, grouping, and formatting into a separate projection layer so report generation can reuse the same scan without rerunning analyzers.

4. Persist one canonical scan per run in the store.
Update the desktop store so each scan record stores the full canonical scan result once, along with any role-projection cache if needed. Do not recompute severity or totals from redacted report fragments when reloading history; preserve the original canonical summary and the grouped breakdown data.

5. Add a role projection function.
Build a function that takes the canonical scan and a role, then returns a role-specific view. For example: Admin gets full detail, Security Analyst gets broad security detail, Developer gets fix-oriented data, Auditor gets redacted evidence plus traceability, and Management gets summary charts and counts only. This projection should not call the scanner again.

6. Make the UI role selector switch projections, not scans.
In the current UI, role selection should simply choose which projection is rendered in the main area. The scan button should run once, and after the scan completes, clicking a role should redraw the same scan data in a different format instead of starting a new scan session.

7. Keep the current layout, but change the data flow behind it.
Do not rebuild the desktop shell. Keep the scan controls, the dashboard, the report preview, the export buttons, and the history panels. Change only the wiring so they read from the stored canonical scan and the current role projection.

8. Make report preview use the current projection.
The preview panel should render the currently selected role's projection from the same scan. If the user switches from Developer to Management, the preview should update instantly from the same canonical scan data, not request a new scan.

9. Make exports use the same projection layer.
HTML, PDF, JSON, SARIF, and any other export should be generated from the current role projection. The same scan result can produce multiple exports, but each export should be formatted according to the selected role's visibility and detail rules.

10. Keep Management summary-only, but powered by the canonical scan.
Management should not show raw finding rows, but it must still receive accurate counts, severity distribution, top vulnerability types, OWASP categories, affected modules, and risk charts from the shared scan data. The management view should be diagrammatic, not blank.

11. Preserve grouped severity breakdowns for drilldown.
The severity distribution should group same vulnerability + same CWE together, and each group should expand to show file name, full path, line number, and module. The grouped data should be derived once from the canonical scan and reused by the UI and exports.

12. Keep raw evidence hidden where required, not removed from the model.
For Management and redacted Auditor views, hide raw detail in presentation only. Do not delete it from the canonical scan. That way a role can display only summary data while the engine still has the full underlying evidence for other projections.

13. Normalize severity only once, then reuse it everywhere.
Compute Critical / High / Medium / Low / Info from the canonical scan and store that distribution on the scan record. Do not let a later role reload flatten it to zero. Role projections should read the same normalized severity distribution or derive a projection-specific subset without changing the original source.

14. Update history to store scan, not role-run duplication.
History entries should point to one scan ID with multiple role views available underneath it. That means the scan history screen shows one scan, and the role tabs inside that scan show different projections. Do not create separate scan records just because the user switched roles.

15. Add a projection cache only if needed.
If rendering becomes expensive, cache the projected views by scan ID and role. The cache should be derived from the canonical scan and invalidated when the scan data changes. The cache is an optimization, not the source of truth.

16. Update the report builder so it can render the same data into multiple report styles.
Combined, Vulnerability, Fixes, Existing, and Finding Details should all be report styles built from the same canonical scan. Each style can expose different parts of the data, but they should all be generated from one scan result and one projection pipeline.

17. Add explicit role rules to the projection layer.
Define what each role sees in a single place. For example: Admin sees everything; Security Analyst sees broad evidence and prioritization; Developer sees fix guidance and grouped evidence; Auditor sees redacted traceable evidence; Management sees charts, counts, and trend summaries only. That policy should be applied consistently in both UI and exports.

18. Refactor the current UI components to consume projection data.
Components like the severity ring, severity table, top OWASP cards, action plan, management snapshot, and drilldown accordions should accept a projection object instead of reading directly from scan execution fragments. That reduces drift and keeps the same UI shell.

19. Keep drilldown behavior within the selected projection.
Clicking a severity group or finding row should jump to the exact detailed section within the current role's view. For Management, that means group-level drilldown and summary tables; for Developer and Admin, that means deeper file/line evidence. The same anchors should work across HTML preview and export.

20. Make role-specific redaction deterministic.
Auditor and Management views should redact the same fields every time. The redaction rules should be deterministic and encoded in the projection layer so the same scan always produces the same redacted output for the same role.

21. Add regression tests before changing behavior broadly.
Add tests for one canonical scan, role projections, management summary accuracy, severity preservation, grouped severity breakdown, and export consistency. Also test that switching roles does not trigger a new scan and that history still shows one scan record.

22. Test with real examples from your current app.
Use a known repo, run one scan, then click each role and confirm the view changes without rescanning. Verify that Management shows charts and counts, Developer shows fix guidance, Auditor shows redacted evidence, and Admin shows the full picture.

23. Verify that the UI no longer depends on role-specific scan execution for its counts.
The final check is simple: the dashboard counts and severity ring should come from the canonical scan summary, not from a role-filtered fragment that can zero itself out. That is the core fix for the blank or zeroed Management view.

24. Only after that, simplify the scan button logic.
Once the data model is stable, clean up the scan button so it creates one canonical scan, saves it, and updates the current projection. The role tabs should be pure view switches at that point.

25. Push in this order.
First the data model, then the store, then the projection layer, then the UI wiring, then the export generator, then the tests, and finally the cleanup pass. That order keeps the app working while we move from "role changes scan" to "role changes report."
