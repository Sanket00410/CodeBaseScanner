const assert = require("node:assert/strict");
const { execFileSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const root = path.resolve(__dirname, "..");
execFileSync("npx", ["tsc", "-p", "tsconfig.main.json"], { cwd: root, stdio: "inherit", shell: process.platform === "win32" });

const { ScanStore } = require(path.join(root, "dist-main", "database", "store.js"));
const { ExportService } = require(path.join(root, "dist-main", "backend", "exportService.js"));

const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "csx-projection-"));
const dbFile = path.join(tempRoot, "store.json");
const exportDir = path.join(tempRoot, "exports");

function finding(id, severity, title, file, line) {
  return {
    finding_uid: id,
    vulnerability_title: title,
    severity,
    cvss_score: severity === "Critical" ? 9.8 : 8.1,
    cwe_id: title.includes("SQL") ? "CWE-89" : "CWE-79",
    owasp_mapping: title.includes("SQL") ? "A03:2021 - Injection" : "A07:2021 - Identification and Authentication Failures",
    file_path: file,
    line_number: line,
    business_impact: "Impact",
    recommendation: "Fix",
    original_code: "secret = true",
    fixed_code: "secret = false",
    patch_preview: "diff --git a/app.py b/app.py",
    rule_id: id,
  };
}

function report() {
  const findings = [
    finding("critical-sql", "Critical", "SQL Injection", "src/app.py", 10),
    finding("high-xss", "High", "Cross-Site Scripting", "src/ui.tsx", 22),
  ];
  const severity = { Critical: 1, High: 1, Medium: 0, Low: 0, Info: 0 };
  return {
    scanner: { name: "CodeSentinelX", version: "test" },
    executive_summary: {
      target_path: "C:/repo",
      generated_at: "2026-04-22T00:00:00.000Z",
      scan_role: "Admin",
      files_scanned: 2,
      total_vulnerabilities: 2,
      deduplicated_vulnerabilities: 2,
      duplicate_findings_removed: 0,
      severity_distribution: severity,
      risk_score: 91,
      risk_rating: "Critical",
      top_vulnerability_types: [
        { type: "SQL Injection", count: 1 },
        { type: "Cross-Site Scripting", count: 1 },
      ],
      top_owasp_categories: [{ owasp_category: "A03:2021 - Injection", count: 1 }],
      affected_modules: [{ module: "src", count: 2, critical: 1, high: 1 }],
      management_summary: {
        total_findings: 2,
        deduplicated_vulnerabilities: 2,
        active_risk_findings: 2,
        severity_distribution: severity,
        severity_distribution_raw: severity,
        severity_breakdown_groups: [
          {
            severity: "Critical",
            count: 1,
            groups: [
              {
                vulnerability: "SQL Injection",
                cwe: "CWE-89",
                count: 1,
                instances: [{ file_name: "app.py", file_path: "src/app.py", line_number: 10, module: "src" }],
              },
            ],
          },
        ],
        risk_score: 91,
        risk_rating: "Critical",
      },
    },
    existing_implementation_report: {
      report_type: "existing_implementation",
      title: "Existing",
      target_path: "C:/repo",
      generated_at: "2026-04-22T00:00:00.000Z",
      summary: {
        implemented_controls: 1,
        category_distribution: { Authentication: 1 },
        coverage_levels: { Implemented: 1 },
        standards_coverage: { "OWASP ASVS": 1 },
      },
      controls: [
        {
          control_id: "CTRL-AUTH-1",
          name: "Authentication guard",
          category: "Authentication",
          description: "Route requires authenticated access.",
          status: "Implemented",
          coverage_level: "Implemented",
          standard_mappings: ["OWASP ASVS"],
          evidence: [{ file_path: "src/app.py", line_number: 10, snippet: "login_required" }],
        },
      ],
      compliance_matrix: [{ standard: "OWASP ASVS", control_count: 1, status: "partial" }],
    },
    vulnerability_fixed_code_report: {
      report_type: "vulnerability_fixed_code",
      title: "Findings",
      target_path: "C:/repo",
      generated_at: "2026-04-22T00:00:00.000Z",
      scan_role: "Admin",
      summary: {
        total_findings: 2,
        raw_findings_total: 2,
        duplicate_findings_removed: 0,
        severity_distribution: severity,
        risk_score: 91,
        risk_rating: "Critical",
        active_risk_findings: 2,
        files_impacted: 2,
        top_vulnerability_types: [
          { type: "SQL Injection", count: 1 },
          { type: "Cross-Site Scripting", count: 1 },
        ],
        top_owasp_categories: [{ owasp_category: "A03:2021 - Injection", count: 1 }],
        affected_modules: [{ module: "src", count: 2, critical: 1, high: 1 }],
        open_findings: 2,
        reviewed_findings: 0,
      },
      findings,
      auto_fix_recommendations: [],
      toolchain_status: {},
    },
  };
}

function reportWithZeroedSummaries() {
  const payload = report();
  const zero = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };
  payload.executive_summary.total_vulnerabilities = 0;
  payload.executive_summary.deduplicated_vulnerabilities = 0;
  payload.executive_summary.severity_distribution = zero;
  payload.executive_summary.top_vulnerability_types = [];
  payload.executive_summary.top_owasp_categories = [];
  payload.executive_summary.affected_modules = [];
  payload.executive_summary.management_summary = {
    total_findings: 0,
    deduplicated_vulnerabilities: 0,
    active_risk_findings: 0,
    severity_distribution: zero,
    severity_distribution_raw: zero,
    severity_breakdown_groups: [],
    risk_score: 0,
    risk_rating: "Informational",
  };
  payload.vulnerability_fixed_code_report.summary.total_findings = 0;
  payload.vulnerability_fixed_code_report.summary.raw_findings_total = 0;
  payload.vulnerability_fixed_code_report.summary.severity_distribution = zero;
  payload.vulnerability_fixed_code_report.summary.top_vulnerability_types = [];
  payload.vulnerability_fixed_code_report.summary.top_owasp_categories = [];
  payload.vulnerability_fixed_code_report.summary.affected_modules = [];
  payload.vulnerability_fixed_code_report.summary.active_risk_findings = 0;
  payload.vulnerability_fixed_code_report.summary.open_findings = 0;
  payload.vulnerability_fixed_code_report.summary.reviewed_findings = 0;
  return payload;
}

function mixedReportWithZeroedSummaries() {
  const payload = reportWithZeroedSummaries();
  payload.vulnerability_fixed_code_report.findings = [
    finding("critical-sql-1", "Critical", "SQL Injection", "api/auth.py", 11),
    finding("critical-sql-2", "Critical", "SQL Injection", "api/user.py", 31),
    finding("high-xss-1", "High", "Cross-Site Scripting", "web/App.tsx", 20),
    finding("medium-crypto-1", "Medium", "Weak Cryptography Usage", "crypto/hash.py", 7),
    finding("low-log-1", "Low", "Sensitive Data Logged", "logger/audit.py", 9),
  ];
  payload.vulnerability_fixed_code_report.findings[3].cwe_id = "CWE-327";
  payload.vulnerability_fixed_code_report.findings[3].owasp_mapping = "A02:2021 - Cryptographic Failures";
  payload.vulnerability_fixed_code_report.findings[4].cwe_id = "CWE-532";
  payload.vulnerability_fixed_code_report.findings[4].owasp_mapping = "A09:2021 - Security Logging and Monitoring Failures";
  return payload;
}

function assertReportLinksResolve(html, label) {
  const ids = new Set();
  for (const match of html.matchAll(/\sid="([^"]+)"/g)) {
    ids.add(match[1]);
  }
  const clickLinks = [...html.matchAll(/<(?:a|button)\b[^>]*(?:alert-link|fix-link|finding-detail-link|existing-control-link|existing-control-evidence-link)[^>]*>/g)].map(
    (match) => match[0],
  );
  assert.ok(clickLinks.length > 0, `${label} should contain clickable drilldown links`);
  for (const link of clickLinks) {
    const target = /data-target-id="([^"]+)"/.exec(link)?.[1];
    const instance = /data-instance-target-id="([^"]+)"/.exec(link)?.[1];
    const href = /href="#([^"]+)"/.exec(link)?.[1];
    assert.ok(target || href, `${label} clickable link should include a target: ${link}`);
    if (target) {
      assert.ok(ids.has(target), `${label} data-target-id should resolve: ${target}`);
    }
    if (instance) {
      assert.ok(ids.has(instance), `${label} data-instance-target-id should resolve: ${instance}`);
    }
    if (href) {
      assert.ok(ids.has(href), `${label} href anchor should resolve: ${href}`);
    }
  }
}

(async () => {
  const store = await ScanStore.create(dbFile);
  await store.addScan({
    scanId: "scan-1",
    projectPath: "C:/repo",
    requestedBy: "test",
    role: "Developer",
    startedAt: "2026-04-22T00:00:00.000Z",
    completedAt: "2026-04-22T00:01:00.000Z",
    report: report(),
    findingStates: {},
  });

  const history = store.listHistory();
  assert.equal(history.length, 1);
  assert.equal(history[0].canonicalScanAvailable, true);
  assert.deepEqual(history[0].roleViewsAvailable, ["Admin", "Security Analyst", "Developer", "Auditor", "Management"]);
  const persistedAfterAdd = JSON.parse(fs.readFileSync(dbFile, "utf-8"));
  assert.deepEqual(Object.keys(persistedAfterAdd.scans[0].projectionCache).sort(), ["Admin", "Auditor", "Developer", "Management", "Security Analyst"].sort());
  for (const projectionRole of ["Admin", "Security Analyst", "Developer", "Auditor", "Management"]) {
    assert.equal(persistedAfterAdd.scans[0].projectionCache[projectionRole].scanner_invoked, false);
    assert.equal(persistedAfterAdd.scans[0].projectionCache[projectionRole].source_scan_id, "scan-1");
  }

  const management = store.getScanView("scan-1", "Management");
  assert.equal(management.role, "Management");
  assert.equal(management.projection.scanner_invoked, false);
  assert.match(management.projection.projection_reason, /canonical scan scan-1/);
  assert.match(management.projection.inclusion_policy, /executive counts/);
  assert.match(management.projection.redaction_policy, /hides raw finding rows/);
  assert.equal(management.report.role_aware_report.metadata.scanner_invoked, false);
  assert.match(management.report.role_aware_report.metadata.inclusion_policy, /executive counts/);
  assert.equal(management.report.vulnerability_fixed_code_report.findings.length, 0);
  assert.equal(management.report.executive_summary.severity_distribution.Critical, 1);
  assert.equal(management.report.executive_summary.severity_distribution.High, 1);

  const admin = store.getScanView("scan-1", "Admin");
  assert.equal(admin.role, "Admin");
  assert.equal(admin.projection.visibility, "full");
  assert.deepEqual(admin.projection.allowed_sections, ["all"]);
  assert.equal(admin.report.vulnerability_fixed_code_report.findings.length, 2);

  const securityAnalyst = store.getScanView("scan-1", "Security Analyst");
  assert.equal(securityAnalyst.role, "Security Analyst");
  assert.equal(securityAnalyst.projection.visibility, "security");
  assert.equal(securityAnalyst.report.vulnerability_fixed_code_report.findings.length, 2);

  const developer = store.getScanView("scan-1", "Developer");
  assert.equal(developer.role, "Developer");
  assert.equal(developer.projection.visibility, "developer");
  assert.match(developer.projection.inclusion_policy, /fix-oriented/);
  assert.equal(developer.report.vulnerability_fixed_code_report.findings.length, 2);
  assert.equal(developer.report.executive_summary.severity_distribution.Critical, 1);

  const auditor = store.getScanView("scan-1", "Auditor");
  assert.equal(auditor.role, "Auditor");
  assert.equal(auditor.projection.visibility, "redacted");
  assert.match(auditor.projection.redaction_policy, /redacts source code/);
  assert.equal(auditor.report.vulnerability_fixed_code_report.findings[0].original_code, "");
  assert.equal(auditor.report.vulnerability_fixed_code_report.findings[0].patch_preview, "");

  const roleViews = ["Admin", "Security Analyst", "Developer", "Auditor", "Management"].map((projectionRole) =>
    store.getScanView("scan-1", projectionRole),
  );
  assert.equal(store.listHistory().length, 1);
  for (const roleView of roleViews) {
    assert.equal(roleView.scanId, "scan-1");
    assert.equal(roleView.canonicalScan.scan_id, "scan-1");
    assert.equal(roleView.projection.source_scan_id, "scan-1");
    assert.equal(roleView.projection.scanner_invoked, false);
    assert.match(roleView.projection.projection_reason, /scanner was not invoked/);
  }

  const rawStoredScan = store.getScanView("scan-1");
  const exportService = new ExportService(exportDir);
  const adminHtml = exportService.renderReportHtml(rawStoredScan, "combined", undefined, "Admin");
  assert.match(adminHtml, /Role Projection/);
  assert.match(adminHtml, /Admin projection includes the complete canonical scan/);
  assert.match(adminHtml, /Top Prioritized Issues/);
  assert.match(adminHtml, /Alerts by Type/);
  assert.match(adminHtml, /Issue Details/);
  assert.match(adminHtml, /class="alert-link"/);
  assert.match(adminHtml, /data-target-id="combined-alert-/);
  assert.match(adminHtml, /data-instance-target-id="combined-alert-instance-/);
  assert.match(adminHtml, /class="report-disclosure combined-issue"/);
  assertReportLinksResolve(adminHtml, "Admin combined report");

  const securityHtml = exportService.renderReportHtml(rawStoredScan, "vulnerability", undefined, "Security Analyst");
  assert.match(securityHtml, /Role Projection/);
  assert.match(securityHtml, /Security Analyst projection includes broad security triage/);
  assert.match(securityHtml, /Alerts by Type/);
  assert.match(securityHtml, /Detailed Findings/);
  assert.match(securityHtml, /class="alert-link"/);
  assert.match(securityHtml, /data-target-id="alert-/);
  assert.match(securityHtml, /data-instance-target-id="alert-instance-/);
  assertReportLinksResolve(securityHtml, "Security Analyst vulnerability report");

  const securityCsvPath = await exportService.exportReport(rawStoredScan, {
    scanId: "scan-1",
    role: "Security Analyst",
    reportType: "vulnerability",
    format: "csv",
  });
  const securityCsv = fs.readFileSync(securityCsvPath, "utf-8");
  assert.match(securityCsv.split("\n")[0], /ProjectionRole,ProjectionVisibility,ProjectionSourceScan,ScannerInvoked/);
  assert.match(securityCsv, /"Security Analyst","security","scan-1","false"/);

  const securitySarifPath = await exportService.exportReport(rawStoredScan, {
    scanId: "scan-1",
    role: "Security Analyst",
    reportType: "vulnerability",
    format: "sarif",
  });
  assert.match(securitySarifPath, /\.sarif$/);
  assert.doesNotMatch(securitySarifPath, /\.sairf$/);
  const securitySarif = JSON.parse(fs.readFileSync(securitySarifPath, "utf-8"));
  assert.equal(securitySarif.runs[0].properties.projectionRole, "Security Analyst");
  assert.equal(securitySarif.runs[0].properties.projectionVisibility, "security");
  assert.equal(securitySarif.runs[0].properties.projectionSourceScan, "scan-1");
  assert.equal(securitySarif.runs[0].properties.scannerInvoked, false);

  const developerHtml = exportService.renderReportHtml(rawStoredScan, "fixes", undefined, "Developer");
  assert.match(developerHtml, /Role Projection/);
  assert.match(developerHtml, /Developer projection includes fix-oriented issue detail/);
  assert.match(developerHtml, /Issue Details/);
  assert.match(developerHtml, /class="fix-link"/);
  assert.match(developerHtml, /data-target-id="fix-/);
  assert.match(developerHtml, /data-instance-target-id="fix-instance-/);
  assertReportLinksResolve(developerHtml, "Developer fixes report");

  const findingDetailsHtml = exportService.renderReportHtml(rawStoredScan, "finding_details", undefined, "Admin");
  assert.match(findingDetailsHtml, /CodeSentinelX Finding Details Report/);
  assert.match(findingDetailsHtml, /Issue Details/);
  assert.match(findingDetailsHtml, /Issue Drill-Down/);
  assert.match(findingDetailsHtml, /class="finding-detail-link"/);
  assert.match(findingDetailsHtml, /data-target-id="finding-detail-/);
  assert.match(findingDetailsHtml, /data-instance-target-id="finding-detail-instance-/);
  assertReportLinksResolve(findingDetailsHtml, "Finding Details report");

  const findingDetailsPdfPath = await exportService.exportReport(rawStoredScan, {
    scanId: "scan-1",
    role: "Admin",
    reportType: "finding_details",
    format: "pdf",
  });
  assert.match(findingDetailsPdfPath, /Admin[\\/]+Full_Scope_Reports/);
  assert.match(findingDetailsPdfPath, /finding_details/);
  assert.match(findingDetailsPdfPath, /\.pdf$/);
  assert.ok(fs.statSync(findingDetailsPdfPath).size > 0);

  const findingDetailsJsonPath = await exportService.exportReport(rawStoredScan, {
    scanId: "scan-1",
    role: "Developer",
    reportType: "finding_details",
    format: "json",
  });
  const findingDetailsPayload = JSON.parse(fs.readFileSync(findingDetailsJsonPath, "utf-8"));
  assert.equal(findingDetailsPayload.projection_metadata.role, "Developer");
  assert.equal(findingDetailsPayload.finding_details_report.rows.length, 2);

  const auditorHtml = exportService.renderReportHtml(rawStoredScan, "existing", undefined, "Auditor");
  assert.match(auditorHtml, /Role Projection/);
  assert.match(auditorHtml, /Auditor projection includes traceable assurance/);
  if (/existing-control(?:-evidence)?-link/.test(auditorHtml)) {
    assertReportLinksResolve(auditorHtml, "Auditor existing report");
  }

  const managementHtml = exportService.renderReportHtml(rawStoredScan, "management", undefined, "Management");
  assert.match(managementHtml, /CodeSentinelX Management Risk Dashboard/);
  assert.match(managementHtml, /Role Projection/);
  assert.match(managementHtml, /Management report coverage:/);
  assert.match(managementHtml, /Trend Over Time/);
  assert.match(managementHtml, /Critical:\s*1/);
  assert.doesNotMatch(managementHtml, /secret = true/);

  const managementJsonPath = await exportService.exportReport(rawStoredScan, {
    scanId: "scan-1",
    role: "Management",
    reportType: "management",
    format: "json",
  });
  assert.match(managementJsonPath, /Management[\\/]+Management_Risk_Dashboard_Reports/);
  const managementPayload = JSON.parse(fs.readFileSync(managementJsonPath, "utf-8"));
  assert.equal(managementPayload.projection_metadata.role, "Management");
  assert.match(managementPayload.projection_metadata.redaction_policy, /hides raw finding rows/);
  assert.equal(managementPayload.executive_summary.scan_role, "Management");
  assert.equal(managementPayload.management_report.summary.total_findings, 2);
  assert.equal(managementPayload.management_report.summary.severity_distribution.Critical, 1);
  assert.equal(managementPayload.executive_summary.severity_distribution.Critical, 1);

  const developerJsonPath = await exportService.exportReport(rawStoredScan, {
    scanId: "scan-1",
    role: "Developer",
    reportType: "fixes",
    format: "json",
  });
  assert.match(developerJsonPath, /Developer[\\/]+Remediation_Reports/);
  const developerPayload = JSON.parse(fs.readFileSync(developerJsonPath, "utf-8"));
  assert.equal(developerPayload.projection_metadata.role, "Developer");
  assert.match(developerPayload.projection_metadata.inclusion_policy, /fix-oriented/);
  assert.equal(developerPayload.executive_summary.scan_role, "Developer");
  assert.equal(developerPayload.original_suggested_fix_report.findings.length, 2);
  assert.equal(developerPayload.original_suggested_fix_report.findings[0].original_code, "secret = true");

  const auditorJsonPath = await exportService.exportReport(rawStoredScan, {
    scanId: "scan-1",
    role: "Auditor",
    reportType: "existing",
    format: "json",
  });
  const auditorPayload = JSON.parse(fs.readFileSync(auditorJsonPath, "utf-8"));
  assert.equal(auditorPayload.projection_metadata.role, "Auditor");
  assert.match(auditorPayload.projection_metadata.redaction_policy, /redacts source code/);

  await store.addScan({
    scanId: "scan-2",
    projectPath: "C:/repo",
    requestedBy: "test",
    role: "Management",
    startedAt: "2026-04-22T00:02:00.000Z",
    completedAt: "2026-04-22T00:03:00.000Z",
    report: reportWithZeroedSummaries(),
    findingStates: {},
  });
  const zeroSummaryManagement = store.getScanView("scan-2", "Management");
  assert.equal(zeroSummaryManagement.report.vulnerability_fixed_code_report.findings.length, 0);
  assert.equal(zeroSummaryManagement.report.executive_summary.total_vulnerabilities, 2);
  assert.equal(zeroSummaryManagement.report.executive_summary.severity_distribution.Critical, 1);
  assert.equal(zeroSummaryManagement.report.executive_summary.severity_distribution.High, 1);
  assert.equal(zeroSummaryManagement.report.executive_summary.management_summary.severity_breakdown_groups.length, 2);

  const zeroSummaryManagementHtml = exportService.renderReportHtml(store.getScanView("scan-2"), "management", undefined, "Management");
  assert.match(zeroSummaryManagementHtml, /CodeSentinelX Management Risk Dashboard/);
  assert.match(zeroSummaryManagementHtml, /Critical:\s*1/);
  assert.match(zeroSummaryManagementHtml, /High:\s*1/);
  assert.match(zeroSummaryManagementHtml, /conic-gradient/);
  assert.match(zeroSummaryManagementHtml, /#ff5b77|#ff9b4b|#ffd65e|#67b8ff|#70d5ab/);
  assert.match(zeroSummaryManagementHtml, /SQL Injection/);
  assert.match(zeroSummaryManagementHtml, /CWE-89/);
  assert.match(zeroSummaryManagementHtml, /File Name/);
  assert.match(zeroSummaryManagementHtml, /File \/ Path/);
  assert.match(zeroSummaryManagementHtml, /Line/);
  assert.match(zeroSummaryManagementHtml, /Module/);
  assert.match(zeroSummaryManagementHtml, /src\/app.py/);
  assert.doesNotMatch(zeroSummaryManagementHtml, /secret = true/);

  await store.addScan({
    scanId: "scan-3",
    projectPath: "C:/repo",
    requestedBy: "test",
    role: "Admin",
    startedAt: "2026-04-22T00:04:00.000Z",
    completedAt: "2026-04-22T00:05:00.000Z",
    report: mixedReportWithZeroedSummaries(),
    findingStates: {},
  });
  const mixedManagement = store.getScanView("scan-3", "Management");
  assert.equal(mixedManagement.report.executive_summary.total_vulnerabilities, 5);
  assert.equal(mixedManagement.report.executive_summary.severity_distribution.Critical, 2);
  assert.equal(mixedManagement.report.executive_summary.severity_distribution.High, 1);
  assert.equal(mixedManagement.report.executive_summary.severity_distribution.Medium, 1);
  assert.equal(mixedManagement.report.executive_summary.severity_distribution.Low, 1);
  const mixedGroups = mixedManagement.report.executive_summary.management_summary.severity_breakdown_groups;
  const criticalGroup = mixedGroups.find((group) => group.severity === "Critical");
  assert.equal(criticalGroup.count, 2);
  assert.equal(criticalGroup.groups.length, 1);
  assert.equal(criticalGroup.groups[0].count, 2);
  assert.equal(criticalGroup.groups[0].instances.length, 2);
  assert.deepEqual(criticalGroup.groups[0].modules, ["api"]);
  const mixedManagementHtml = exportService.renderReportHtml(store.getScanView("scan-3"), "management", undefined, "Management");
  assert.match(mixedManagementHtml, /CodeSentinelX Management Risk Dashboard/);
  assert.match(mixedManagementHtml, /Critical:\s*2/);
  assert.match(mixedManagementHtml, /High:\s*1/);
  assert.match(mixedManagementHtml, /Medium:\s*1/);
  assert.match(mixedManagementHtml, /Low:\s*1/);
  assert.match(mixedManagementHtml, /#ff5b77|#ff9b4b|#ffd65e|#67b8ff|#70d5ab/);
  assert.match(mixedManagementHtml, /api\/auth.py/);
  assert.match(mixedManagementHtml, /api\/user.py/);
  assert.doesNotMatch(mixedManagementHtml, /secret = true/);

  fs.rmSync(tempRoot, { recursive: true, force: true });
})().catch((error) => {
  console.error(error);
  fs.rmSync(tempRoot, { recursive: true, force: true });
  process.exit(1);
});
