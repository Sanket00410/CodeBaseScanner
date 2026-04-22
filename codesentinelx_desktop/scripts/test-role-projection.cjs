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
    owasp_mapping: title.includes("SQL") ? "A03:2025 - Injection" : "A07:2025 - Identification and Authentication Failures",
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
      top_owasp_categories: [{ owasp_category: "A03:2025 - Injection", count: 1 }],
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
      summary: { implemented_controls: 0, category_distribution: {}, coverage_levels: {}, standards_coverage: {} },
      controls: [],
      compliance_matrix: [],
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
        top_owasp_categories: [{ owasp_category: "A03:2025 - Injection", count: 1 }],
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

  const rawStoredScan = store.getScanView("scan-1");
  const exportService = new ExportService(exportDir);
  const adminHtml = exportService.renderReportHtml(rawStoredScan, "combined", undefined, "Admin");
  assert.match(adminHtml, /Role Projection/);
  assert.match(adminHtml, /Admin projection includes the complete canonical scan/);
  assert.match(adminHtml, /Top Prioritized Issues/);

  const securityHtml = exportService.renderReportHtml(rawStoredScan, "vulnerability", undefined, "Security Analyst");
  assert.match(securityHtml, /Role Projection/);
  assert.match(securityHtml, /Security Analyst projection includes broad security triage/);

  const developerHtml = exportService.renderReportHtml(rawStoredScan, "fixes", undefined, "Developer");
  assert.match(developerHtml, /Role Projection/);
  assert.match(developerHtml, /Developer projection includes fix-oriented issue detail/);

  const auditorHtml = exportService.renderReportHtml(rawStoredScan, "existing", undefined, "Auditor");
  assert.match(auditorHtml, /Role Projection/);
  assert.match(auditorHtml, /Auditor projection includes traceable assurance/);

  const managementHtml = exportService.renderReportHtml(rawStoredScan, "combined", undefined, "Management");
  assert.match(managementHtml, /Management Snapshot/);
  assert.match(managementHtml, /Role Projection/);
  assert.match(managementHtml, /Management projection includes executive counts/);
  assert.match(managementHtml, /Critical:\s*1/);
  assert.doesNotMatch(managementHtml, /secret = true/);

  const managementJsonPath = await exportService.exportReport(rawStoredScan, {
    scanId: "scan-1",
    role: "Management",
    reportType: "combined",
    format: "json",
  });
  assert.match(managementJsonPath, /Management[\\/]+Executive_Summary_Reports/);
  const managementPayload = JSON.parse(fs.readFileSync(managementJsonPath, "utf-8"));
  assert.equal(managementPayload.executive_summary.scan_role, "Management");
  assert.equal(managementPayload.vulnerability_fixed_code_report.findings.length, 0);
  assert.equal(managementPayload.executive_summary.severity_distribution.Critical, 1);

  const developerJsonPath = await exportService.exportReport(rawStoredScan, {
    scanId: "scan-1",
    role: "Developer",
    reportType: "fixes",
    format: "json",
  });
  assert.match(developerJsonPath, /Developer[\\/]+Remediation_Reports/);
  const developerPayload = JSON.parse(fs.readFileSync(developerJsonPath, "utf-8"));
  assert.equal(developerPayload.executive_summary.scan_role, "Developer");
  assert.equal(developerPayload.original_suggested_fix_report.findings.length, 2);
  assert.equal(developerPayload.original_suggested_fix_report.findings[0].original_code, "secret = true");

  fs.rmSync(tempRoot, { recursive: true, force: true });
})().catch((error) => {
  console.error(error);
  fs.rmSync(tempRoot, { recursive: true, force: true });
  process.exit(1);
});
