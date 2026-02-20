import { createWriteStream, mkdirSync } from "node:fs";
import { promises as fs } from "node:fs";
import path from "node:path";

import PDFDocument from "pdfkit";

import { ExportRequest, ScanView, VulnerabilityFinding } from "./types";

interface FileAggregate {
  file: string;
  folder: string;
  counts: Record<string, number>;
  total: number;
}

interface AlertGroup {
  id: string;
  title: string;
  severity: string;
  cwe: string;
  owasp: string;
  count: number;
  findings: VulnerabilityFinding[];
}

const SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"];
const SEVERITY_TO_SARIF: Record<string, string> = {
  Critical: "error",
  High: "error",
  Medium: "warning",
  Low: "note",
  Info: "note",
};

export class ExportService {
  constructor(private readonly outputDir: string) {
    mkdirSync(this.outputDir, { recursive: true });
  }

  resolveOutputPath(scan: ScanView, reportType: ExportRequest["reportType"], format: ExportRequest["format"]): string {
    const stamp = scan.completedAt.replaceAll(":", "-").replaceAll(".", "-");
    const fileName = `codesentinelx_${reportType}_${scan.scanId}_${stamp}.${format}`;
    return path.join(this.outputDir, fileName);
  }

  renderReportHtml(scan: ScanView, reportType: ExportRequest["reportType"]): string {
    return this.toHtml(scan, reportType);
  }

  async exportReport(scan: ScanView, request: ExportRequest): Promise<string> {
    const destination = this.resolveOutputPath(scan, request.reportType, request.format);

    if (request.format === "json") {
      await fs.writeFile(destination, JSON.stringify(this.selectPayload(scan, request.reportType), null, 2), "utf-8");
      return destination;
    }
    if (request.format === "csv") {
      await fs.writeFile(destination, this.toCsv(scan, request.reportType), "utf-8");
      return destination;
    }
    if (request.format === "patch") {
      await fs.writeFile(destination, this.toPatch(scan), "utf-8");
      return destination;
    }
    if (request.format === "html") {
      await fs.writeFile(destination, this.toHtml(scan, request.reportType), "utf-8");
      return destination;
    }
    if (request.format === "sarif") {
      if (request.reportType === "existing" || request.reportType === "fixes") {
        throw new Error("SARIF export is available only for vulnerability or combined reports.");
      }
      await fs.writeFile(destination, JSON.stringify(this.toSarif(scan), null, 2), "utf-8");
      return destination;
    }
    if (request.format === "pdf") {
      await this.writePdf(scan, destination, request.reportType);
      return destination;
    }
    throw new Error(`Unsupported export format: ${request.format}`);
  }

  private selectPayload(scan: ScanView, reportType: ExportRequest["reportType"]): unknown {
    if (reportType === "existing") {
      return {
        scanner: scan.report.scanner,
        executive_summary: scan.report.executive_summary,
        existing_implementation_report: scan.report.existing_implementation_report,
      };
    }
    if (reportType === "vulnerability") {
      return {
        scanner: scan.report.scanner,
        executive_summary: scan.report.executive_summary,
        vulnerability_fixed_code_report: scan.report.vulnerability_fixed_code_report,
      };
    }
    if (reportType === "fixes") {
      return {
        scanner: scan.report.scanner,
        executive_summary: scan.report.executive_summary,
        original_suggested_fix_report: {
          title: "CodeSentinelX Original and Suggested Fix Report",
          target_path: scan.report.vulnerability_fixed_code_report.target_path,
          generated_at: scan.report.vulnerability_fixed_code_report.generated_at,
          total_findings: scan.report.vulnerability_fixed_code_report.summary.total_findings,
          findings: sortedFindings(scan.report.vulnerability_fixed_code_report.findings || []).map((item) => ({
            finding_uid: item.finding_uid,
            severity: item.severity,
            cvss_score: item.cvss_score,
            vulnerability_title: item.vulnerability_title || item.vulnerability_type || "Issue",
            file_path: normalizePath(item.file_path),
            line_number: item.line_number || 1,
            cwe_id: item.cwe_id || "N/A",
            owasp_mapping: item.owasp_mapping || "N/A",
            recommendation: item.recommendation || "",
            original_code: item.original_code || "",
            suggested_fix: item.fixed_code || "",
            patch_preview: item.patch_preview || "",
          })),
        },
      };
    }
    return scan.report;
  }

  private toCsv(scan: ScanView, reportType: ExportRequest["reportType"]): string {
    if (reportType === "existing") {
      const header = "Control,Category,Coverage,Standards\n";
      const rows = scan.report.existing_implementation_report.controls.map((item) =>
        csvLine([item.name, item.category, item.coverage_level, item.standard_mappings.join(" | ")]),
      );
      return `${header}${rows.join("\n")}\n`;
    }

    if (reportType === "fixes") {
      const findings = sortedFindings(scan.report.vulnerability_fixed_code_report.findings || []);
      const header = "Severity,CVSS,Issue,File,Line,CWE,OWASP,OriginalCode,SuggestedFix,PatchPreview\n";
      const rows = findings.map((item) =>
        csvLine([
          item.severity,
          String(item.cvss_score || 0),
          item.vulnerability_title || item.vulnerability_type || "Issue",
          normalizePath(item.file_path),
          String(item.line_number || 1),
          item.cwe_id || "N/A",
          item.owasp_mapping || "N/A",
          singleLine(item.original_code || ""),
          singleLine(item.fixed_code || ""),
          singleLine(item.patch_preview || ""),
        ]),
      );
      return `${header}${rows.join("\n")}\n`;
    }

    const findings = sortedFindings(scan.report.vulnerability_fixed_code_report.findings || []);
    const header = "Severity,CVSS,Issue,CWE,OWASP,File,Folder,Line,Status,Recommendation\n";
    const rows = findings.map((item) =>
      csvLine([
        item.severity,
        String(item.cvss_score || 0),
        item.vulnerability_title || item.vulnerability_type || "Issue",
        item.cwe_id || "N/A",
        item.owasp_mapping || "N/A",
        normalizePath(item.file_path),
        folderFromPath(item.file_path),
        String(item.line_number || 1),
        item.status || "Open",
        item.recommendation || "",
      ]),
    );
    return `${header}${rows.join("\n")}\n`;
  }

  private toPatch(scan: ScanView): string {
    const chunks = sortedFindings(scan.report.vulnerability_fixed_code_report.findings || [])
      .map((item) => (item.patch_preview || "").trim())
      .filter((item) => item.length > 0);
    return chunks.length > 0 ? `${chunks.join("\n\n")}\n` : "# No patch previews available.\n";
  }

  private toHtml(scan: ScanView, reportType: ExportRequest["reportType"]): string {
    if (reportType === "existing") {
      return renderExistingHtml(scan);
    }
    if (reportType === "vulnerability") {
      return renderVulnerabilityHtml(scan);
    }
    if (reportType === "fixes") {
      return renderFixesHtml(scan);
    }
    return renderCombinedHtml(scan);
  }

  private toSarif(scan: ScanView): unknown {
    const findings = sortedFindings(scan.report.vulnerability_fixed_code_report.findings || []);
    const rules = new Map<string, Record<string, unknown>>();
    const results: Array<Record<string, unknown>> = [];

    for (const finding of findings) {
      const ruleId = finding.rule_id || "CODESENTINELX-RULE";
      if (!rules.has(ruleId)) {
        rules.set(ruleId, {
          id: ruleId,
          shortDescription: { text: finding.vulnerability_title || finding.vulnerability_type || "Security finding" },
          fullDescription: { text: finding.business_impact || "" },
          help: { text: finding.recommendation || "" },
          properties: {
            tags: [finding.owasp_mapping || "N/A", finding.cwe_id || "N/A"],
          },
        });
      }

      results.push({
        ruleId,
        level: SEVERITY_TO_SARIF[finding.severity] || "warning",
        message: { text: finding.vulnerability_title || finding.vulnerability_type || "Security finding" },
        locations: [
          {
            physicalLocation: {
              artifactLocation: { uri: normalizePath(finding.file_path) },
              region: { startLine: Math.max(1, Number(finding.line_number || 1)) },
            },
          },
        ],
      });
    }

    return {
      version: "2.1.0",
      $schema: "https://json.schemastore.org/sarif-2.1.0.json",
      runs: [
        {
          tool: {
            driver: {
              name: scan.report.scanner.name,
              version: scan.report.scanner.version,
              rules: Array.from(rules.values()),
            },
          },
          results,
        },
      ],
    };
  }

  private async writePdf(scan: ScanView, outputPath: string, reportType: ExportRequest["reportType"]): Promise<void> {
    await new Promise<void>((resolve, reject) => {
      const doc = new PDFDocument({ margin: 32, size: "A4" });
      const stream = createWriteStream(outputPath);
      doc.pipe(stream);
      stream.on("finish", resolve);
      stream.on("error", reject);
      doc.on("error", reject);

      if (reportType === "existing") {
        writeExistingPdf(doc, scan);
      } else if (reportType === "vulnerability") {
        writeVulnerabilityPdf(doc, scan);
      } else if (reportType === "fixes") {
        writeFixesPdf(doc, scan);
      } else {
        writeCombinedPdf(doc, scan);
      }

      doc.end();
    });
  }
}

function writeExistingPdf(doc: PDFKit.PDFDocument, scan: ScanView): void {
  const report = scan.report.existing_implementation_report;
  const summary = report.summary;
  const profileCompliance = report.profile_compliance || scan.report.profile_compliance;
  doc.fontSize(18).text("CodeSentinelX Existing Security Implementation Report");
  doc.moveDown(0.3).fontSize(10).text(`Target: ${report.target_path}`);
  doc.text(`Generated: ${report.generated_at}`);
  doc.moveDown(0.6).fontSize(12).text("Summary");
  doc.fontSize(10).text(`Implemented Controls: ${summary.implemented_controls}`);
  doc.text(`Categories: ${Object.keys(summary.category_distribution || {}).length}`);
  doc.text(`Standards Covered: ${Object.keys(summary.standards_coverage || {}).length}`);
  writeWrapped(doc, "Category Distribution:", 9);
  for (const [name, count] of Object.entries(summary.category_distribution || {})) {
    writeWrapped(doc, `- ${name}: ${count}`, 9);
  }
  writeWrapped(doc, "Coverage Levels:", 9);
  for (const [name, count] of Object.entries(summary.coverage_levels || {})) {
    writeWrapped(doc, `- ${name}: ${count}`, 9);
  }
  writeWrapped(doc, "Standards Coverage:", 9);
  for (const [name, count] of Object.entries(summary.standards_coverage || {})) {
    writeWrapped(doc, `- ${name}: ${count}`, 9);
  }

  if (profileCompliance) {
    doc.moveDown(0.6).fontSize(12).text("Profile-Based OWASP/ASVS/WSTG Coverage");
    writeWrapped(
      doc,
      `Profile: ${profileCompliance.scan_profile_label} (${profileCompliance.scan_profile})`,
      9,
    );
    writeWrapped(
      doc,
      `Versions -> OWASP Top 10: ${profileCompliance.framework_versions?.owasp_top_10 || "N/A"} | API Top 10: ${profileCompliance.framework_versions?.owasp_api_top_10 || "N/A"} | ASVS: ${profileCompliance.framework_versions?.asvs || "N/A"} | WSTG: ${profileCompliance.framework_versions?.wstg || "N/A"}`,
      8,
    );
    for (const framework of profileCompliance.frameworks || []) {
      writeWrapped(
        doc,
        `- ${framework.label} | applicable=${framework.applicable ? "yes" : "no"} | covered=${framework.summary.covered}, gap=${framework.summary.gap}, n/a=${framework.summary.not_applicable}`,
        8,
      );
      for (const row of (framework.rows || []).slice(0, 30)) {
        writeWrapped(
          doc,
          `    ${row.id} ${row.title} -> ${row.status} (findings=${row.finding_count}, controls=${row.control_count})`,
          8,
        );
      }
      if ((framework.rows || []).length > 30) {
        writeWrapped(doc, `    ... ${framework.rows.length - 30} additional rows not shown.`, 8);
      }
    }
  }

  doc.moveDown(0.6).fontSize(12).text("Controls");

  for (const control of report.controls.slice(0, 120)) {
    writeWrapped(doc, `- ${control.name} (${control.category}) [${control.coverage_level}]`, 9);
  }
}

function writeVulnerabilityPdf(doc: PDFKit.PDFDocument, scan: ScanView): void {
  const report = scan.report.vulnerability_fixed_code_report;
  const findings = sortedFindings(report.findings || []);
  const groups = groupByAlert(findings);
  const fileAgg = aggregateFiles(findings);
  const moduleAgg = report.summary.affected_modules || [];
  const owaspAgg = report.summary.top_owasp_categories || [];
  const actionPlan = scan.report.executive_summary.recommended_action_plan || [];

  doc.fontSize(18).text("CodeSentinelX Vulnerability Report (ZAP-Style)");
  doc.moveDown(0.3).fontSize(10).text(`Target: ${report.target_path}`);
  doc.text(`Generated: ${report.generated_at}`);
  doc.text(`Risk Score: ${report.summary.risk_score} (${report.summary.risk_rating})`);
  doc.moveDown(0.7).fontSize(12).text("Summary of Alerts");
  for (const severity of SEVERITY_ORDER) {
    const count = report.summary.severity_distribution?.[severity] || 0;
    writeWrapped(doc, `- ${severity}: ${count}`, 10);
  }

  doc.moveDown(0.5).fontSize(12).text("Top Affected Files");
  for (const item of fileAgg.slice(0, 25)) {
    writeWrapped(
      doc,
      `- ${item.file}: ${item.total} total (${item.counts.Critical || 0} critical, ${item.counts.High || 0} high)`,
      9,
    );
  }

  doc.moveDown(0.5).fontSize(12).text("Top OWASP Categories");
  for (const item of owaspAgg.slice(0, 12)) {
    writeWrapped(doc, `- ${item.owasp_category}: ${item.count}`, 9);
  }

  doc.moveDown(0.5).fontSize(12).text("Affected Modules");
  for (const item of moduleAgg.slice(0, 20)) {
    writeWrapped(
      doc,
      `- ${String(item.module)}: ${String(item.count)} total (${String(item.critical)} critical, ${String(item.high)} high)`,
      9,
    );
  }

  doc.moveDown(0.5).fontSize(12).text("Action Plan");
  for (const step of actionPlan.slice(0, 10)) {
    writeWrapped(doc, `- ${step}`, 9);
  }

  doc.moveDown(0.5).fontSize(12).text("Alert Details");
  for (const group of groups.slice(0, 50)) {
    writeWrapped(doc, `[${group.severity}] ${group.title} - ${group.count} instance(s)`, 10);
    writeWrapped(doc, `CWE: ${group.cwe} | OWASP: ${group.owasp}`, 8);
    const lead = group.findings[0];
    const leadExtended = lead as VulnerabilityFinding & { description?: string; tool?: string };
    writeWrapped(doc, `Tool: ${leadExtended.tool || "scanner"}`, 8);
    writeWrapped(doc, `Description: ${singleLine(leadExtended.description || "N/A")}`, 8);
    writeWrapped(doc, `Impact: ${lead.business_impact || "N/A"}`, 8);
    writeWrapped(doc, `Recommendation: ${lead.recommendation || "N/A"}`, 8);
    writeWrapped(doc, "Instances:", 8);
    for (const finding of group.findings.slice(0, 10)) {
      const findingExtended = finding as VulnerabilityFinding & { tool?: string };
      writeWrapped(
        doc,
        `  - ${normalizePath(finding.file_path)}:${finding.line_number} | ${finding.status || "Open"} | ${findingExtended.tool || "scanner"}`,
        8,
      );
    }
    doc.moveDown(0.25);
  }

  const moduleSeverity = groupFindingsByModuleSeverity(findings);
  doc.moveDown(0.5).fontSize(12).text("Module Severity Drill-down");
  writeWrapped(
    doc,
    "This section maps each module severity count to exact findings (file and line) for PDF evidence.",
    8,
  );
  for (const entry of moduleSeverity.slice(0, 220)) {
    writeWrapped(
      doc,
      `[${entry.severity}] ${entry.module} - ${entry.findings.length} finding(s)`,
      9,
    );
    for (const finding of entry.findings.slice(0, 35)) {
      writeWrapped(
        doc,
        `  - ${normalizePath(finding.file_path)}:${finding.line_number || 1} | ${finding.vulnerability_title || finding.vulnerability_type || "Issue"}`,
        8,
      );
    }
    if (entry.findings.length > 35) {
      writeWrapped(doc, `  ... ${entry.findings.length - 35} additional finding(s) not shown.`, 8);
    }
    doc.moveDown(0.2);
  }
}

function writeFixesPdf(doc: PDFKit.PDFDocument, scan: ScanView): void {
  const report = scan.report.vulnerability_fixed_code_report;
  const findings = sortedFindings(report.findings || []);

  doc.fontSize(18).text("CodeSentinelX Original and Suggested Fix Report");
  doc.moveDown(0.3).fontSize(10).text(`Target: ${report.target_path}`);
  doc.text(`Generated: ${report.generated_at}`);
  doc.text(`Total Findings: ${report.summary.total_findings}`);
  doc.moveDown(0.7).fontSize(12).text("Fix Guidance Queue");

  for (const finding of findings.slice(0, 240)) {
    writeWrapped(
      doc,
      `[${finding.severity}] ${finding.vulnerability_title || finding.vulnerability_type || "Issue"} | CVSS ${(finding.cvss_score || 0).toFixed(1)}`,
      10,
    );
    writeWrapped(
      doc,
      `Location: ${normalizePath(finding.file_path)}:${finding.line_number || 1} | ${finding.cwe_id || "N/A"} | ${finding.owasp_mapping || "N/A"}`,
      8,
    );
    writeWrapped(doc, `Recommendation: ${finding.recommendation || "N/A"}`, 8);
    writeWrapped(doc, "Original Code:", 8);
    for (const line of codeSnippetLines(finding.original_code || "Snippet unavailable.", 12, 180)) {
      writeWrapped(doc, `  ${line}`, 8);
    }
    writeWrapped(doc, "Suggested Fix:", 8);
    for (const line of codeSnippetLines(finding.fixed_code || "No direct fix available.", 12, 180)) {
      writeWrapped(doc, `  ${line}`, 8);
    }
    if (finding.patch_preview) {
      writeWrapped(doc, "Patch Preview:", 8);
      for (const line of codeSnippetLines(finding.patch_preview, 12, 180)) {
        writeWrapped(doc, `  ${line}`, 8);
      }
    }
    doc.moveDown(0.35);
  }

  if (findings.length > 240) {
    writeWrapped(doc, `Truncated after 240 entries. Additional findings: ${findings.length - 240}`, 9);
  }
}

function writeCombinedPdf(doc: PDFKit.PDFDocument, scan: ScanView): void {
  doc.fontSize(18).text("CodeSentinelX Combined Security Report");
  doc.moveDown(0.3).fontSize(10).text(`Target: ${scan.report.executive_summary.target_path}`);
  doc.text(`Risk Score: ${scan.report.executive_summary.risk_score} (${scan.report.executive_summary.risk_rating})`);
  doc.moveDown(0.7).fontSize(11).text("Use separate Existing and Vulnerability reports for full evidence.");
}

function writeWrapped(doc: PDFKit.PDFDocument, text: string, fontSize: number): void {
  if (doc.y > doc.page.height - 52) {
    doc.addPage();
  }
  doc.fontSize(fontSize).text(text, { width: doc.page.width - 64 });
}

function renderExistingHtml(scan: ScanView): string {
  const report = scan.report.existing_implementation_report;
  const profileCompliance = report.profile_compliance || scan.report.profile_compliance;
  const summaryRows = Object.entries(report.summary).map(
    ([key, value]) => `<tr><td>${escapeHtml(key.replaceAll("_", " "))}</td><td>${renderSummaryValue(value)}</td></tr>`,
  );

  const controlRows = report.controls.map(
    (control) =>
      `<tr><td>${escapeHtml(control.name)}</td><td>${escapeHtml(control.category)}</td><td>${escapeHtml(control.coverage_level)}</td><td>${escapeHtml(control.standard_mappings.join(", "))}</td></tr>`,
  );

  const profileHeader = profileCompliance
    ? `<p class="meta"><strong>Profile:</strong> ${escapeHtml(profileCompliance.scan_profile_label)} (${escapeHtml(profileCompliance.scan_profile)})</p>
  <p class="meta"><strong>Framework Versions:</strong> OWASP Top 10 ${escapeHtml(profileCompliance.framework_versions.owasp_top_10)} | API Top 10 ${escapeHtml(profileCompliance.framework_versions.owasp_api_top_10)} | ASVS ${escapeHtml(profileCompliance.framework_versions.asvs)} | WSTG ${escapeHtml(profileCompliance.framework_versions.wstg)}</p>`
    : "";

  const profileFrameworks = profileCompliance
    ? profileCompliance.frameworks
        .map((framework) => {
          const rows = framework.rows
            .map(
              (row) => `<tr>
      <td>${escapeHtml(row.id)}</td>
      <td>${escapeHtml(row.title)}</td>
      <td>${escapeHtml(String(row.status).replaceAll("_", " "))}</td>
      <td>${row.finding_count}</td>
      <td>${row.control_count}</td>
      <td>${row.count}</td>
    </tr>`,
            )
            .join("");
          return `<h3>${escapeHtml(framework.label)} (${framework.applicable ? "Applicable" : "Not Applicable"})</h3>
    <p class="meta">Covered: ${framework.summary.covered} | Gap: ${framework.summary.gap} | Not Applicable: ${framework.summary.not_applicable}</p>
    <table>
      <thead><tr><th>ID</th><th>Category</th><th>Status</th><th>Findings</th><th>Controls</th><th>Total</th></tr></thead>
      <tbody>${rows || "<tr><td colspan='6'>No mapping rows available.</td></tr>"}</tbody>
    </table>`;
        })
        .join("")
    : "<p>No profile-based compliance coverage generated for this scan.</p>";

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>CodeSentinelX Existing Security Report</title>
  <style>
    body{font-family:Arial,Helvetica,sans-serif;font-size:13px;color:#101820;background:#f3f5f7;padding:14px}
    h1{font-size:28px;margin:0 0 8px}
    h2{font-size:19px;margin:16px 0 8px}
    table{border-collapse:collapse;width:100%}
    th,td{border:1px solid #ccd3da;padding:6px;vertical-align:top}
    th{background:#4b5968;color:#fff;text-align:left}
    td{background:#fff}
    td table{margin:0;width:100%}
    td table th{background:#e6ecf2;color:#243447}
    td ul{margin:0;padding-left:18px}
    .meta{margin:4px 0}
  </style>
</head>
<body>
  <h1>CodeSentinelX Existing Security Implementation Report</h1>
  <p class="meta"><strong>Target:</strong> ${escapeHtml(report.target_path)}</p>
  <p class="meta"><strong>Generated:</strong> ${escapeHtml(report.generated_at)}</p>
  ${profileHeader}

  <h2>Coverage Summary</h2>
  <table>
    <thead><tr><th>Metric</th><th>Value</th></tr></thead>
    <tbody>${summaryRows.join("")}</tbody>
  </table>

  <h2>Profile-Based Coverage (OWASP / API / ASVS / WSTG)</h2>
  ${profileFrameworks}

  <h2>Implemented Controls</h2>
  <table>
    <thead><tr><th>Control</th><th>Category</th><th>Coverage</th><th>Standards</th></tr></thead>
    <tbody>${controlRows.join("") || "<tr><td colspan='4'>No controls detected.</td></tr>"}</tbody>
  </table>
</body>
</html>`;
}

function renderVulnerabilityHtml(scan: ScanView): string {
  const report = scan.report.vulnerability_fixed_code_report;
  const findings = sortedFindings(report.findings || []);
  const grouped = groupByAlert(findings);
  const fileAgg = aggregateFiles(findings);
  const moduleAgg = report.summary.affected_modules || [];
  const owaspAgg = report.summary.top_owasp_categories || [];
  const actionPlan = scan.report.executive_summary.recommended_action_plan || [];
  const moduleSeverityCatalog = groupFindingsByModuleSeverity(findings);
  const drillData = findings.map((finding) => ({
    finding_uid: finding.finding_uid,
    severity: finding.severity,
    issue: finding.vulnerability_title || finding.vulnerability_type || "Issue",
    file: normalizePath(finding.file_path),
    folder: folderFromPath(finding.file_path),
    module: moduleFromFinding(finding),
    line: finding.line_number || 1,
    cwe: finding.cwe_id || "N/A",
    owasp: finding.owasp_mapping || "N/A",
    status: finding.status || "Open",
    tool: finding.tool || "scanner",
  }));

  const summaryRows = SEVERITY_ORDER.map((severity) => {
    const count = report.summary.severity_distribution?.[severity] || 0;
    return `<tr><td class="risk-${severity.toLowerCase()}">${severity}</td><td align="center">${count}</td></tr>`;
  }).join("");

  const alertRows = grouped
    .map(
      (group) => `<tr>
    <td class="risk-${group.severity.toLowerCase()}">${escapeHtml(group.severity)}</td>
    <td><button type="button" class="alert-link" data-alert-id="${escapeHtml(group.id)}">${escapeHtml(group.title)}</button></td>
    <td align="center">${group.count}</td>
    <td>${escapeHtml(group.cwe)}</td>
    <td>${escapeHtml(group.owasp)}</td>
  </tr>`,
    )
    .join("");

  const fileRows = fileAgg
    .map(
      (item) => `<tr>
    <td>${escapeHtml(item.file)}</td>
    <td>${escapeHtml(item.folder)}</td>
    <td align="center">${drillCountCell("file", item.file, "Critical", item.counts.Critical || 0)}</td>
    <td align="center">${drillCountCell("file", item.file, "High", item.counts.High || 0)}</td>
    <td align="center">${drillCountCell("file", item.file, "Medium", item.counts.Medium || 0)}</td>
    <td align="center">${drillCountCell("file", item.file, "Low", item.counts.Low || 0)}</td>
    <td align="center">${drillCountCell("file", item.file, "Info", item.counts.Info || 0)}</td>
    <td align="center">${drillCountCell("file", item.file, "All", item.total)}</td>
  </tr>`,
    )
    .join("");

  const moduleRows = moduleAgg
    .map(
      (item) => `<tr>
    <td>${escapeHtml(String(item.module || "root"))}</td>
    <td align="center">${drillCountCell("module", String(item.module || "root"), "All", Number(item.count || 0))}</td>
    <td align="center">${drillCountCell("module", String(item.module || "root"), "Critical", Number(item.critical || 0))}</td>
    <td align="center">${drillCountCell("module", String(item.module || "root"), "High", Number(item.high || 0))}</td>
  </tr>`,
    )
    .join("");

  const owaspRows = owaspAgg
    .map(
      (item) => `<tr>
    <td>${escapeHtml(String(item.owasp_category || "N/A"))}</td>
    <td align="center">${String(item.count || 0)}</td>
  </tr>`,
    )
    .join("");

  const actionRows = actionPlan.map((item) => `<li>${escapeHtml(item)}</li>`).join("");

  const details = grouped
    .map((group) => {
      const lead = group.findings[0];
      const leadExtended = lead as VulnerabilityFinding & { description?: string; tool?: string };
      const instanceRows = group.findings
        .map(
          (finding) => `<tr>
      <td>${escapeHtml(normalizePath(finding.file_path))}</td>
      <td>${escapeHtml(folderFromPath(finding.file_path))}</td>
      <td align="center">${finding.line_number || 1}</td>
      <td>${escapeHtml(finding.status || "Open")}</td>
      <td>${escapeHtml(String((finding as VulnerabilityFinding & { tool?: string }).tool || "scanner"))}</td>
      <td>${escapeHtml(finding.cwe_id || "N/A")}</td>
      <td>${escapeHtml(finding.owasp_mapping || "N/A")}</td>
    </tr>`,
        )
        .join("");

      return `<section id="${escapeHtml(group.id)}" class="alert-section hidden-section">
    <h3>[${escapeHtml(group.severity)}] ${escapeHtml(group.title)} (${group.count})</h3>
    <table class="results">
      <tr><th width="20%">CWE</th><td>${escapeHtml(group.cwe)}</td></tr>
      <tr><th>OWASP</th><td>${escapeHtml(group.owasp)}</td></tr>
      <tr><th>Description</th><td>${escapeHtml(leadExtended.description || "N/A")}</td></tr>
      <tr><th>Business Impact</th><td>${escapeHtml(lead.business_impact || "N/A")}</td></tr>
      <tr><th>Recommendation</th><td>${escapeHtml(lead.recommendation || "N/A")}</td></tr>
      <tr><th>Source Tool</th><td>${escapeHtml(leadExtended.tool || "scanner")}</td></tr>
    </table>
    <h4>Instances</h4>
    <table class="results">
      <thead>
        <tr><th>File Path</th><th>Folder</th><th>Line</th><th>Status</th><th>Tool</th><th>CWE</th><th>OWASP</th></tr>
      </thead>
      <tbody>
        ${instanceRows || "<tr><td colspan='7'>No instances</td></tr>"}
      </tbody>
    </table>
  </section>`;
    })
    .join("");

  const moduleEvidenceSections = moduleSeverityCatalog
    .slice(0, 220)
    .map((entry) => {
      const rows = entry.findings
        .slice(0, 80)
        .map(
          (finding) => `<tr>
      <td>${escapeHtml(normalizePath(finding.file_path))}</td>
      <td align="center">${finding.line_number || 1}</td>
      <td>${escapeHtml(finding.vulnerability_title || finding.vulnerability_type || "Issue")}</td>
      <td>${escapeHtml(finding.cwe_id || "N/A")}</td>
      <td>${escapeHtml(finding.owasp_mapping || "N/A")}</td>
      <td>${escapeHtml(finding.status || "Open")}</td>
    </tr>`,
        )
        .join("");
      const hiddenCount = Math.max(0, entry.findings.length - 80);
      const hiddenRow =
        hiddenCount > 0
          ? `<tr><td colspan="6" class="muted">${hiddenCount} additional finding(s) hidden for readability.</td></tr>`
          : "";
      return `<details class="evidence-block" open id="${escapeHtml(drillAnchorId("module", entry.module, entry.severity))}">
    <summary>[${escapeHtml(entry.severity)}] ${escapeHtml(entry.module)} (${entry.findings.length})</summary>
    <table>
      <thead><tr><th>File</th><th>Line</th><th>Issue</th><th>CWE</th><th>OWASP</th><th>Status</th></tr></thead>
      <tbody>${rows || "<tr><td colspan='6' class='muted'>No findings.</td></tr>"}${hiddenRow}</tbody>
    </table>
  </details>`;
    })
    .join("");
  const moduleEvidenceOverflow = Math.max(0, moduleSeverityCatalog.length - 220);

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>CodeSentinelX Vulnerability Report</title>
  <style>
    :root{--bg:#071321;--panel:#0d1d33;--line:#294a6c;--text:#dce9f7;--muted:#95afc8;--critical:#ff5b77;--high:#ff9b4b;--medium:#ffd65e;--low:#67b8ff;--info:#70d5ab;--accent:#35c7ff}
    *{box-sizing:border-box}
    body{font-family:"Segoe UI",Tahoma,sans-serif;font-size:13px;color:var(--text);background:radial-gradient(circle at 20% -20%,#1c3a60,var(--bg) 45%);padding:14px;margin:0}
    h1{font-size:32px;margin:0 0 8px}
    h2{font-size:21px;margin:0 0 10px}
    h3{font-size:16px;margin:12px 0 6px}
    h4{font-size:14px;margin:10px 0 6px}
    .panel{background:linear-gradient(160deg,#0f2139,var(--panel));border:1px solid var(--line);border-radius:12px;padding:14px;margin-bottom:12px}
    .meta{margin:3px 0;color:var(--muted)}
    .summary-cards{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:8px;margin-top:10px}
    .card{border:1px solid var(--line);border-radius:10px;background:#0b1a2d;padding:10px}
    .card strong{display:block;font-size:12px;color:var(--muted);margin-bottom:4px}
    .card span{font-size:28px;font-weight:700;color:var(--text)}
    .layout{display:grid;grid-template-columns:1fr 1fr;gap:10px}
    table{border-collapse:collapse;width:100%;margin-bottom:10px}
    th,td{border:1px solid var(--line);padding:7px 8px;vertical-align:top}
    th{background:#10253f;color:#c6d9ec;text-align:left;cursor:pointer}
    td{background:#0b1a2d}
    tr:hover td{background:#0f2540}
    .summary{max-width:520px}
    .risk-critical{background:rgba(255,91,119,0.25);color:#ffdce3;font-weight:bold}
    .risk-high{background:rgba(255,155,75,0.25);color:#ffe2c9;font-weight:bold}
    .risk-medium{background:rgba(255,214,94,0.26);color:#fff4c8;font-weight:bold}
    .risk-low{background:rgba(103,184,255,0.26);color:#dcefff;font-weight:bold}
    .risk-info{background:rgba(112,213,171,0.26);color:#dff9ef;font-weight:bold}
    .results th{width:18%}
    .toolbar{display:flex;gap:8px;align-items:center;margin:6px 0 10px;flex-wrap:wrap}
    input{background:#071424;border:1px solid var(--line);border-radius:8px;color:var(--text);padding:7px 10px;min-width:240px}
    .chart-wrap{display:grid;grid-template-columns:320px 1fr;gap:12px;align-items:center}
    .legend-item{display:flex;align-items:center;gap:8px;color:var(--muted);margin:6px 0}
    .dot{width:10px;height:10px;border-radius:50%}
    .bars{display:grid;gap:8px}
    .bar-row{display:grid;grid-template-columns:220px 1fr auto;gap:8px;align-items:center}
    .bar-track{height:12px;border:1px solid var(--line);border-radius:999px;background:#071424;overflow:hidden}
    .bar-fill{height:100%;background:linear-gradient(90deg,#1f88ff,var(--accent))}
    .bar-label{color:var(--muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
    .hidden-section{display:none}
    .alert-link{background:none;border:none;color:var(--accent);cursor:pointer;text-decoration:underline;font:inherit;padding:0}
    .drill-link{background:none;border:none;color:var(--accent);cursor:pointer;text-decoration:underline;font:inherit;padding:0}
    .code{margin:0;white-space:pre-wrap;word-break:break-word;font-family:Consolas,monospace;background:#06101a;border:1px solid var(--line);border-radius:8px;padding:8px;color:#dce9f7}
    .drill-state{margin-bottom:8px;color:var(--muted)}
    .evidence-block{border:1px solid var(--line);border-radius:10px;padding:8px;background:#0b1a2d;margin-bottom:10px}
    .evidence-block summary{cursor:pointer;font-weight:700}
    .muted{color:var(--muted)}
    @media (max-width:1200px){.layout,.summary-cards,.chart-wrap{grid-template-columns:1fr}}
  </style>
</head>
<body>
  <section class="panel">
    <h1>CodeSentinelX Vulnerability Dashboard</h1>
    <p class="meta"><strong>Target:</strong> ${escapeHtml(report.target_path)}</p>
    <p class="meta"><strong>Generated:</strong> ${escapeHtml(report.generated_at)}</p>
    <p class="meta"><strong>Risk Score:</strong> ${report.summary.risk_score} (${escapeHtml(report.summary.risk_rating)})</p>
    <div class="summary-cards">
      <article class="card"><strong>Total Findings</strong><span>${report.summary.total_findings}</span></article>
      <article class="card"><strong>Files Impacted</strong><span>${report.summary.files_impacted}</span></article>
      <article class="card"><strong>Critical</strong><span>${report.summary.severity_distribution?.Critical || 0}</span></article>
      <article class="card"><strong>High</strong><span>${report.summary.severity_distribution?.High || 0}</span></article>
      <article class="card"><strong>Active Risk</strong><span>${report.summary.active_risk_findings}</span></article>
    </div>
  </section>

  <section class="panel">
    <div class="layout">
      <div>
        <h2>Severity Summary</h2>
        <table id="severitySummary" class="summary">
          <thead><tr><th data-sort-index="0" data-sort-type="text">Risk Level</th><th data-sort-index="1" data-sort-type="number" align="center">Count</th></tr></thead>
          <tbody>${summaryRows}</tbody>
        </table>
      </div>
      <div>
        <h2>Severity Distribution</h2>
        <div class="chart-wrap">
          <canvas id="severityChart" width="280" height="280"></canvas>
          <div id="severityLegend"></div>
        </div>
      </div>
    </div>
  </section>

  <section class="panel">
    <h2>OWASP Category Counts</h2>
    <div class="layout">
      <div>
        <div class="toolbar"><input id="owaspSearch" type="search" placeholder="Search OWASP category" /></div>
        <table id="owaspTable" class="summary">
          <thead><tr><th data-sort-index="0" data-sort-type="text">OWASP Category</th><th data-sort-index="1" data-sort-type="number" align="center">Count</th></tr></thead>
          <tbody>${owaspRows || "<tr><td colspan='2' class='muted'>No OWASP category data.</td></tr>"}</tbody>
        </table>
      </div>
      <div>
        <h3>Top Categories Chart</h3>
        <div id="owaspBars" class="bars"></div>
      </div>
    </div>
  </section>

  <section class="panel">
    <h2>Affected Modules</h2>
    <div class="toolbar"><input id="moduleSearch" type="search" placeholder="Search module (click severity counts for exact issues)" /></div>
    <table id="moduleTable">
      <thead><tr><th data-sort-index="0" data-sort-type="text">Module</th><th data-sort-index="1" data-sort-type="number">Total</th><th data-sort-index="2" data-sort-type="number">Critical</th><th data-sort-index="3" data-sort-type="number">High</th></tr></thead>
      <tbody>${moduleRows || "<tr><td colspan='4' class='muted'>No affected modules.</td></tr>"}</tbody>
    </table>
  </section>

  <section class="panel">
    <h2>Alerts by Type</h2>
    <table id="alertTable">
      <thead><tr><th data-sort-index="0" data-sort-type="text">Risk</th><th data-sort-index="1" data-sort-type="text">Alert</th><th data-sort-index="2" data-sort-type="number" align="center">Instances</th><th data-sort-index="3" data-sort-type="text">CWE</th><th data-sort-index="4" data-sort-type="text">OWASP</th></tr></thead>
      <tbody>${alertRows || "<tr><td colspan='5' class='muted'>No findings.</td></tr>"}</tbody>
    </table>
    <p class="muted">Click an alert title to expand/collapse detailed findings.</p>
  </section>

  <section class="panel">
    <h2>Affected Files and Folders</h2>
    <div class="toolbar"><input id="fileSearch" type="search" placeholder="Search file or folder (click severity counts for exact issues)" /></div>
    <table id="fileTable">
      <thead><tr><th data-sort-index="0" data-sort-type="text">File</th><th data-sort-index="1" data-sort-type="text">Folder</th><th data-sort-index="2" data-sort-type="number">Critical</th><th data-sort-index="3" data-sort-type="number">High</th><th data-sort-index="4" data-sort-type="number">Medium</th><th data-sort-index="5" data-sort-type="number">Low</th><th data-sort-index="6" data-sort-type="number">Info</th><th data-sort-index="7" data-sort-type="number">Total</th></tr></thead>
      <tbody>${fileRows || "<tr><td colspan='8' class='muted'>No affected files.</td></tr>"}</tbody>
    </table>
  </section>

  <section class="panel">
    <h2>Module/File Severity Drill-down</h2>
    <p class="drill-state" id="drillState">Click any count in Affected Modules or Affected Files to list exact findings.</p>
    <table id="drillTable">
      <thead><tr><th>Severity</th><th>Issue</th><th>File</th><th>Module</th><th>Line</th><th>CWE</th><th>OWASP</th><th>Status</th></tr></thead>
      <tbody><tr><td colspan="8" class="muted">No drill-down selection.</td></tr></tbody>
    </table>
  </section>

  <section class="panel">
    <h2>Module Severity Evidence (PDF-ready)</h2>
    <p class="muted">This section enumerates exact findings for each module severity count and is included in PDF exports.</p>
    ${moduleEvidenceSections || "<p class='muted'>No module severity evidence available.</p>"}
    ${moduleEvidenceOverflow > 0 ? `<p class="muted">${moduleEvidenceOverflow} additional module/severity groups not shown in this export.</p>` : ""}
  </section>

  <section class="panel">
    <h2>Action Plan</h2>
    <ol>${actionRows || "<li>No action plan available.</li>"}</ol>
  </section>

  <section class="panel">
    <h2>Detailed Findings</h2>
    ${details || "<p class='muted'>No findings available.</p>"}
  </section>

  <script>
    (function () {
      var severityColors = { Critical: "#ff5b77", High: "#ff9b4b", Medium: "#ffd65e", Low: "#67b8ff", Info: "#70d5ab" };
      var drillData = ${jsonForScript(drillData)};

      function sortTable(table, index, type, asc) {
        var tbody = table.querySelector("tbody");
        if (!tbody) return;
        var rows = Array.from(tbody.querySelectorAll("tr"));
        rows.sort(function (a, b) {
          var av = (a.children[index] && a.children[index].textContent ? a.children[index].textContent : "").trim();
          var bv = (b.children[index] && b.children[index].textContent ? b.children[index].textContent : "").trim();
          if (type === "number") {
            var an = Number(av || 0);
            var bn = Number(bv || 0);
            return asc ? an - bn : bn - an;
          }
          av = av.toLowerCase();
          bv = bv.toLowerCase();
          if (av < bv) return asc ? -1 : 1;
          if (av > bv) return asc ? 1 : -1;
          return 0;
        });
        rows.forEach(function (row) { tbody.appendChild(row); });
      }

      function initTable(tableId, searchId) {
        var table = document.getElementById(tableId);
        if (!table) return;
        var headers = table.querySelectorAll("th[data-sort-index]");
        headers.forEach(function (header) {
          header.addEventListener("click", function () {
            var index = Number(header.getAttribute("data-sort-index") || 0);
            var type = header.getAttribute("data-sort-type") || "text";
            var asc = header.getAttribute("data-dir") !== "asc";
            header.setAttribute("data-dir", asc ? "asc" : "desc");
            sortTable(table, index, type, asc);
          });
        });
        if (!searchId) return;
        var input = document.getElementById(searchId);
        if (!input) return;
        input.addEventListener("input", function () {
          var query = (input.value || "").toLowerCase();
          var tbody = table.querySelector("tbody");
          if (!tbody) return;
          Array.from(tbody.querySelectorAll("tr")).forEach(function (row) {
            var text = (row.textContent || "").toLowerCase();
            row.style.display = !query || text.indexOf(query) >= 0 ? "" : "none";
          });
        });
      }

      function toggleAlert(id) {
        if (!id) return;
        var section = document.getElementById(id);
        if (section) section.classList.toggle("hidden-section");
      }

      function renderDrillDown(scope, key, severity) {
        var state = document.getElementById("drillState");
        var table = document.getElementById("drillTable");
        if (!table) return;
        var tbody = table.querySelector("tbody");
        if (!tbody) return;

        var normalizedKey = String(key || "").trim();
        var selected = drillData.filter(function (item) {
          if (scope === "module" && item.module !== normalizedKey) return false;
          if (scope === "file" && item.file !== normalizedKey) return false;
          if (severity && severity !== "All" && item.severity !== severity) return false;
          return true;
        });

        selected.sort(function (a, b) {
          var order = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };
          var r = (order[a.severity] || 99) - (order[b.severity] || 99);
          if (r !== 0) return r;
          if (a.file !== b.file) return a.file < b.file ? -1 : 1;
          return Number(a.line || 0) - Number(b.line || 0);
        });

        if (state) {
          state.textContent = "Drill-down: " + scope + " = " + normalizedKey + " | severity = " + severity + " | findings = " + selected.length;
        }

        if (!selected.length) {
          tbody.innerHTML = "<tr><td colspan='8' class='muted'>No findings matched this drill-down.</td></tr>";
          return;
        }

        function escapeCell(value) {
          return String(value == null ? "" : value)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#39;");
        }

        tbody.innerHTML = selected.slice(0, 600).map(function (item) {
          return "<tr>"
            + "<td>" + escapeCell(item.severity) + "</td>"
            + "<td>" + escapeCell(item.issue) + "</td>"
            + "<td>" + escapeCell(item.file) + "</td>"
            + "<td>" + escapeCell(item.module) + "</td>"
            + "<td align='center'>" + item.line + "</td>"
            + "<td>" + escapeCell(item.cwe) + "</td>"
            + "<td>" + escapeCell(item.owasp) + "</td>"
            + "<td>" + escapeCell(item.status) + "</td>"
            + "</tr>";
        }).join("");

        var anchorId = "drill-" + scope + "-" + normalizedKey.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 80) + "-" + String(severity || "all").toLowerCase();
        var evidence = document.getElementById(anchorId);
        if (evidence && evidence.scrollIntoView) {
          evidence.scrollIntoView({ behavior: "smooth", block: "start" });
        }
      }

      function drawSeverityChart() {
        var canvas = document.getElementById("severityChart");
        if (!canvas || !canvas.getContext) return;
        var summaryRows = Array.from(document.querySelectorAll("#severitySummary tbody tr"));
        var labels = [];
        var counts = [];
        summaryRows.forEach(function (row) {
          var cells = row.children;
          if (cells.length >= 2) {
            labels.push((cells[0].textContent || "").trim());
            counts.push(Number((cells[1].textContent || "0").trim()));
          }
        });
        var total = counts.reduce(function (sum, value) { return sum + value; }, 0);
        var ctx = canvas.getContext("2d");
        if (!ctx) return;
        ctx.clearRect(0, 0, canvas.width, canvas.height);
        if (total <= 0) return;
        var cx = canvas.width / 2;
        var cy = canvas.height / 2;
        var outer = Math.min(cx, cy) - 8;
        var inner = outer * 0.58;
        var start = -Math.PI / 2;
        labels.forEach(function (label, idx) {
          var value = counts[idx];
          if (value <= 0) return;
          var arc = (value / total) * Math.PI * 2;
          ctx.beginPath();
          ctx.moveTo(cx, cy);
          ctx.arc(cx, cy, outer, start, start + arc);
          ctx.closePath();
          ctx.fillStyle = severityColors[label] || "#70d5ab";
          ctx.fill();
          start += arc;
        });
        ctx.beginPath();
        ctx.arc(cx, cy, inner, 0, Math.PI * 2);
        ctx.fillStyle = "#0b1a2d";
        ctx.fill();
        ctx.fillStyle = "#dce9f7";
        ctx.font = "700 26px Segoe UI";
        ctx.textAlign = "center";
        ctx.fillText(String(total), cx, cy + 8);
        ctx.textAlign = "left";
        var legend = document.getElementById("severityLegend");
        if (legend) {
          legend.innerHTML = labels.map(function (label, idx) {
            return "<div class='legend-item'><span class='dot' style='background:" + (severityColors[label] || "#70d5ab") + "'></span><span>" + label + ": " + counts[idx] + "</span></div>";
          }).join("");
        }
      }

      function drawOwaspBars() {
        var rows = Array.from(document.querySelectorAll("#owaspTable tbody tr")).map(function (row) {
          var cells = row.children;
          return { label: cells[0] ? (cells[0].textContent || "").trim() : "", count: Number(cells[1] ? (cells[1].textContent || "0").trim() : "0") };
        }).filter(function (item) { return item.label; });
        var root = document.getElementById("owaspBars");
        if (!root) return;
        if (!rows.length) {
          root.innerHTML = "<p class='muted'>No OWASP data available.</p>";
          return;
        }
        var max = rows.reduce(function (current, item) { return Math.max(current, item.count); }, 1);
        root.innerHTML = rows.slice(0, 10).map(function (item) {
          var width = Math.max(2, Math.round((item.count / max) * 100));
          return "<div class='bar-row'><div class='bar-label' title='" + item.label + "'>" + item.label + "</div><div class='bar-track'><div class='bar-fill' style='width:" + width + "%'></div></div><div>" + item.count + "</div></div>";
        }).join("");
      }

      document.querySelectorAll(".alert-link").forEach(function (btn) {
        btn.addEventListener("click", function () {
          toggleAlert(btn.getAttribute("data-alert-id"));
        });
      });

      document.querySelectorAll(".drill-link").forEach(function (btn) {
        btn.addEventListener("click", function (event) {
          if (event && event.preventDefault) {
            event.preventDefault();
          }
          renderDrillDown(
            btn.getAttribute("data-drill-scope"),
            btn.getAttribute("data-drill-key"),
            btn.getAttribute("data-drill-severity")
          );
        });
      });

      initTable("severitySummary");
      initTable("owaspTable", "owaspSearch");
      initTable("moduleTable", "moduleSearch");
      initTable("alertTable");
      initTable("fileTable", "fileSearch");
      initTable("drillTable");
      drawSeverityChart();
      drawOwaspBars();
    })();
  </script>
</body>
</html>`;
}

function renderFixesHtml(scan: ScanView): string {
  const report = scan.report.vulnerability_fixed_code_report;
  const findings = sortedFindings(report.findings || []);

  const severityRows = SEVERITY_ORDER.map((severity) => {
    const count = report.summary.severity_distribution?.[severity] || 0;
    return `<tr><td>${severity}</td><td align="center">${count}</td></tr>`;
  }).join("");

  const rows = findings
    .map(
      (finding, index) => `<tr>
    <td>${index + 1}</td>
    <td><span class="sev sev-${finding.severity}">${escapeHtml(finding.severity)}</span></td>
    <td>${escapeHtml(finding.vulnerability_title || finding.vulnerability_type || "Issue")}</td>
    <td>${escapeHtml(normalizePath(finding.file_path))}</td>
    <td align="center">${finding.line_number || 1}</td>
    <td>${escapeHtml(finding.cwe_id || "N/A")}</td>
    <td>${escapeHtml(finding.owasp_mapping || "N/A")}</td>
    <td><a class="fix-link" href="#fix-${escapeHtml(finding.finding_uid)}">Open</a></td>
  </tr>`,
    )
    .join("");

  const detailSections = findings
    .map(
      (finding) => `<section id="fix-${escapeHtml(finding.finding_uid)}" class="fix-detail">
    <h3>[${escapeHtml(finding.severity)}] ${escapeHtml(finding.vulnerability_title || finding.vulnerability_type || "Issue")}</h3>
    <p><strong>Location:</strong> ${escapeHtml(normalizePath(finding.file_path))}:${finding.line_number || 1}</p>
    <p><strong>CWE:</strong> ${escapeHtml(finding.cwe_id || "N/A")} | <strong>OWASP:</strong> ${escapeHtml(finding.owasp_mapping || "N/A")} | <strong>CVSS:</strong> ${(finding.cvss_score || 0).toFixed(1)}</p>
    <p><strong>Recommendation:</strong> ${escapeHtml(finding.recommendation || "N/A")}</p>
    <div class="code-grid">
      <div>
        <h4>Original Code</h4>
        <pre>${escapeHtml(finding.original_code || "Snippet unavailable.")}</pre>
      </div>
      <div>
        <h4>Suggested Fix</h4>
        <pre>${escapeHtml(finding.fixed_code || "No direct fix available.")}</pre>
      </div>
    </div>
    <h4>Patch Preview</h4>
    <pre>${escapeHtml(finding.patch_preview || "No patch preview available.")}</pre>
  </section>`,
    )
    .join("");

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>CodeSentinelX Original and Suggested Fix Report</title>
  <style>
    :root{--bg:#071321;--panel:#0d1d33;--line:#294a6c;--text:#dce9f7;--muted:#95afc8;--critical:#ff5b77;--high:#ff9b4b;--medium:#ffd65e;--low:#67b8ff;--info:#70d5ab;--accent:#35c7ff}
    *{box-sizing:border-box}
    body{font-family:"Segoe UI",Tahoma,sans-serif;font-size:13px;color:var(--text);background:radial-gradient(circle at 20% -20%,#1c3a60,var(--bg) 45%);padding:14px;margin:0}
    h1{font-size:31px;margin:0 0 8px}
    h2{font-size:20px;margin:0 0 8px}
    h3{font-size:16px;margin:10px 0 6px}
    h4{font-size:14px;margin:8px 0 6px}
    .panel{background:linear-gradient(160deg,#0f2139,var(--panel));border:1px solid var(--line);border-radius:12px;padding:14px;margin-bottom:12px}
    .meta{margin:3px 0;color:var(--muted)}
    table{border-collapse:collapse;width:100%;margin-bottom:10px}
    th,td{border:1px solid var(--line);padding:7px 8px;vertical-align:top}
    th{background:#10253f;color:#c6d9ec;text-align:left;cursor:pointer}
    td{background:#0b1a2d}
    tr:hover td{background:#0f2540}
    .toolbar{display:flex;gap:8px;align-items:center;margin:6px 0 10px;flex-wrap:wrap}
    input{background:#071424;border:1px solid var(--line);border-radius:8px;color:var(--text);padding:7px 10px;min-width:300px}
    .fix-link{color:var(--accent);cursor:pointer;text-decoration:underline}
    .fix-detail{border:1px solid var(--line);border-radius:10px;background:#0b1a2d;padding:12px;margin-bottom:10px}
    .code-grid{display:grid;gap:10px;grid-template-columns:1fr 1fr}
    pre{margin:0;white-space:pre-wrap;word-break:break-word;font-family:Consolas,monospace;background:#06101a;border:1px solid var(--line);border-radius:8px;padding:8px;color:#dce9f7;max-height:320px;overflow:auto}
    .sev{border-radius:999px;padding:3px 8px;font-size:11px;font-weight:700}
    .sev-Critical{background:rgba(255,91,119,0.25);color:#ffdce3}
    .sev-High{background:rgba(255,155,75,0.25);color:#ffe2c9}
    .sev-Medium{background:rgba(255,214,94,0.26);color:#fff4c8}
    .sev-Low{background:rgba(103,184,255,0.26);color:#dcefff}
    .sev-Info{background:rgba(112,213,171,0.26);color:#dff9ef}
    @media (max-width:1200px){.code-grid{grid-template-columns:1fr}}
  </style>
</head>
<body>
  <section class="panel">
    <h1>CodeSentinelX Original and Suggested Fix Report</h1>
    <p class="meta"><strong>Target:</strong> ${escapeHtml(report.target_path)}</p>
    <p class="meta"><strong>Generated:</strong> ${escapeHtml(report.generated_at)}</p>
    <p class="meta"><strong>Total Findings:</strong> ${report.summary.total_findings}</p>
  </section>

  <section class="panel">
    <h2>Severity Summary</h2>
    <table id="severityTable">
      <thead><tr><th data-sort-index="0" data-sort-type="text">Severity</th><th data-sort-index="1" data-sort-type="number">Count</th></tr></thead>
      <tbody>${severityRows}</tbody>
    </table>
  </section>

  <section class="panel">
    <h2>Fix Queue</h2>
    <div class="toolbar"><input id="fixSearch" type="search" placeholder="Search by issue, file, CWE, OWASP" /></div>
    <table id="fixTable">
      <thead><tr><th data-sort-index="0" data-sort-type="number">#</th><th data-sort-index="1" data-sort-type="text">Severity</th><th data-sort-index="2" data-sort-type="text">Issue</th><th data-sort-index="3" data-sort-type="text">File</th><th data-sort-index="4" data-sort-type="number">Line</th><th data-sort-index="5" data-sort-type="text">CWE</th><th data-sort-index="6" data-sort-type="text">OWASP</th><th>Details</th></tr></thead>
      <tbody>${rows || "<tr><td colspan='8'>No findings available.</td></tr>"}</tbody>
    </table>
  </section>

  <section class="panel">
    <h2>Original and Suggested Fix Details</h2>
    ${detailSections || "<p>No fix entries found.</p>"}
  </section>

  <script>
    (function () {
      function sortTable(table, index, type, asc) {
        var tbody = table.querySelector("tbody");
        if (!tbody) return;
        var rows = Array.from(tbody.querySelectorAll("tr"));
        rows.sort(function (a, b) {
          var av = (a.children[index] && a.children[index].textContent ? a.children[index].textContent : "").trim();
          var bv = (b.children[index] && b.children[index].textContent ? b.children[index].textContent : "").trim();
          if (type === "number") {
            var an = Number(av || 0);
            var bn = Number(bv || 0);
            return asc ? an - bn : bn - an;
          }
          av = av.toLowerCase();
          bv = bv.toLowerCase();
          if (av < bv) return asc ? -1 : 1;
          if (av > bv) return asc ? 1 : -1;
          return 0;
        });
        rows.forEach(function (row) { tbody.appendChild(row); });
      }

      function initSortable(tableId) {
        var table = document.getElementById(tableId);
        if (!table) return;
        var headers = table.querySelectorAll("th[data-sort-index]");
        headers.forEach(function (header) {
          header.addEventListener("click", function () {
            var index = Number(header.getAttribute("data-sort-index") || 0);
            var type = header.getAttribute("data-sort-type") || "text";
            var asc = header.getAttribute("data-dir") !== "asc";
            header.setAttribute("data-dir", asc ? "asc" : "desc");
            sortTable(table, index, type, asc);
          });
        });
      }

      function initSearch() {
        var input = document.getElementById("fixSearch");
        var table = document.getElementById("fixTable");
        if (!input || !table) return;
        var tbody = table.querySelector("tbody");
        if (!tbody) return;
        input.addEventListener("input", function () {
          var query = (input.value || "").toLowerCase();
          Array.from(tbody.querySelectorAll("tr")).forEach(function (row) {
            var text = (row.textContent || "").toLowerCase();
            row.style.display = !query || text.indexOf(query) >= 0 ? "" : "none";
          });
        });
      }

      initSortable("severityTable");
      initSortable("fixTable");
      initSearch();
    })();
  </script>
</body>
</html>`;
}

function renderCombinedHtml(scan: ScanView): string {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>CodeSentinelX Combined Report</title>
  <style>
    body{font-family:Arial,Helvetica,sans-serif;background:#f3f5f7;color:#111;padding:18px}
    .card{max-width:920px;margin:0 auto;background:#fff;border:1px solid #c5ccd3;border-radius:8px;padding:18px}
  </style>
</head>
<body>
  <div class="card">
    <h1>CodeSentinelX Combined Security Report</h1>
    <p><strong>Target:</strong> ${escapeHtml(scan.report.executive_summary.target_path)}</p>
    <p><strong>Risk Score:</strong> ${scan.report.executive_summary.risk_score} (${escapeHtml(scan.report.executive_summary.risk_rating)})</p>
    <p>For full evidence, export separate Existing Security, Vulnerability, and Original/Suggested Fix reports.</p>
  </div>
</body>
</html>`;
}

function sortedFindings(findings: VulnerabilityFinding[]): VulnerabilityFinding[] {
  return [...findings].sort((a, b) => {
    const severityDiff = SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity);
    if (severityDiff !== 0) {
      return severityDiff;
    }
    if ((b.cvss_score || 0) !== (a.cvss_score || 0)) {
      return (b.cvss_score || 0) - (a.cvss_score || 0);
    }
    const pathDiff = normalizePath(a.file_path).localeCompare(normalizePath(b.file_path));
    if (pathDiff !== 0) {
      return pathDiff;
    }
    return (a.line_number || 0) - (b.line_number || 0);
  });
}

function groupByAlert(findings: VulnerabilityFinding[]): AlertGroup[] {
  const map = new Map<string, AlertGroup>();
  for (const finding of findings) {
    const title = finding.vulnerability_title || finding.vulnerability_type || "Issue";
    const key = `${title}::${finding.cwe_id || "N/A"}::${finding.owasp_mapping || "N/A"}`;
    if (!map.has(key)) {
      map.set(key, {
        id: slugify(key),
        title,
        severity: finding.severity,
        cwe: finding.cwe_id || "N/A",
        owasp: finding.owasp_mapping || "N/A",
        count: 0,
        findings: [],
      });
    }

    const entry = map.get(key)!;
    entry.findings.push(finding);
    entry.count += 1;
    if (SEVERITY_ORDER.indexOf(finding.severity) < SEVERITY_ORDER.indexOf(entry.severity)) {
      entry.severity = finding.severity;
    }
  }

  return [...map.values()].sort((a, b) => {
    const severityDiff = SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity);
    if (severityDiff !== 0) {
      return severityDiff;
    }
    return b.count - a.count;
  });
}

function aggregateFiles(findings: VulnerabilityFinding[]): FileAggregate[] {
  const map = new Map<string, FileAggregate>();
  for (const finding of findings) {
    const file = normalizePath(finding.file_path);
    if (!map.has(file)) {
      map.set(file, {
        file,
        folder: folderFromPath(file),
        counts: { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 },
        total: 0,
      });
    }
    const entry = map.get(file)!;
    entry.counts[finding.severity] = (entry.counts[finding.severity] || 0) + 1;
    entry.total += 1;
  }

  return [...map.values()].sort((a, b) => b.total - a.total).slice(0, 120);
}

function moduleFromFinding(finding: VulnerabilityFinding): string {
  const explicitModule = String(finding.affected_module || "").trim();
  if (explicitModule) {
    return explicitModule;
  }

  const normalized = normalizePath(finding.file_path);
  if (!normalized) {
    return ".";
  }

  const httpMatch = normalized.match(/^https?:\/\/([^/]+)(\/.*)?$/i);
  if (httpMatch) {
    const pathPart = httpMatch[2] || "";
    const first = pathPart.replace(/^\/+/, "").split("/")[0];
    return first || httpMatch[1];
  }

  const sshMatch = normalized.match(/^ssh:\/\/([^/]+)(\/.*)?$/i);
  if (sshMatch) {
    const pathPart = sshMatch[2] || "";
    const first = pathPart.replace(/^\/+/, "").split("/")[0];
    return first || sshMatch[1];
  }

  let value = normalized;
  if (/^[a-zA-Z]:\//.test(value)) {
    value = value.slice(3);
  }
  value = value.replace(/^\/+/, "");
  const first = value.split("/")[0];
  return first || ".";
}

function groupFindingsByModuleSeverity(
  findings: VulnerabilityFinding[],
): Array<{ module: string; severity: string; findings: VulnerabilityFinding[] }> {
  const map = new Map<string, { module: string; severity: string; findings: VulnerabilityFinding[] }>();

  for (const finding of findings) {
    const module = moduleFromFinding(finding);
    const severities: string[] = ["All", finding.severity];
    for (const severity of severities) {
      const key = `${module}::${severity}`;
      if (!map.has(key)) {
        map.set(key, { module, severity, findings: [] });
      }
      map.get(key)!.findings.push(finding);
    }
  }

  return [...map.values()].sort((a, b) => {
    const rank = (value: string): number => (value === "All" ? -1 : SEVERITY_ORDER.indexOf(value));
    const severityDiff = rank(a.severity) - rank(b.severity);
    if (severityDiff !== 0) {
      return severityDiff;
    }
    if (b.findings.length !== a.findings.length) {
      return b.findings.length - a.findings.length;
    }
    return a.module.localeCompare(b.module);
  });
}

function folderFromPath(value: string): string {
  const normalized = normalizePath(value);
  const schemeMatch = normalized.match(/^https?:\/\/[^/]+/i);
  if (schemeMatch) {
    const rest = normalized.slice(schemeMatch[0].length);
    const idx = rest.lastIndexOf("/");
    if (idx <= 0) {
      return schemeMatch[0];
    }
    return `${schemeMatch[0]}${rest.slice(0, idx)}`;
  }

  const idx = normalized.lastIndexOf("/");
  if (idx <= 0) {
    return ".";
  }
  return normalized.slice(0, idx);
}

function normalizePath(value: string): string {
  return String(value || "").replaceAll("\\", "/");
}

function singleLine(value: string): string {
  return String(value || "").replace(/\s+/g, " ").trim();
}

function codeSnippetLines(value: string, maxLines = 8, maxChars = 160): string[] {
  const normalized = String(value || "").replace(/\r\n/g, "\n").replace(/\r/g, "\n");
  const rawLines = normalized.split("\n").map((line) => line.trim()).filter((line) => line.length > 0);
  if (rawLines.length === 0) {
    return ["N/A"];
  }
  const sliced = rawLines.slice(0, maxLines).map((line) => (line.length > maxChars ? `${line.slice(0, maxChars)}...` : line));
  if (rawLines.length > maxLines) {
    sliced.push("...");
  }
  return sliced;
}

function drillAnchorId(scope: "module" | "file", key: string, severity: string): string {
  const normalized = String(key || "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 80);
  return `drill-${scope}-${normalized || "root"}-${String(severity || "all").toLowerCase()}`;
}

function drillCountCell(scope: "module" | "file", key: string, severity: string, count: number): string {
  const safeCount = Math.max(0, Number(count || 0));
  if (safeCount <= 0) {
    return "0";
  }
  const anchor = scope === "module" ? drillAnchorId(scope, key, severity) : "drillTable";
  return `<a href="#${escapeHtml(anchor)}" class="drill-link" data-drill-scope="${escapeHtml(scope)}" data-drill-key="${escapeHtml(
    key,
  )}" data-drill-severity="${escapeHtml(severity)}">${safeCount}</a>`;
}

function jsonForScript(value: unknown): string {
  return JSON.stringify(value)
    .replace(/</g, "\\u003c")
    .replace(/>/g, "\\u003e")
    .replace(/&/g, "\\u0026")
    .replace(/\u2028/g, "\\u2028")
    .replace(/\u2029/g, "\\u2029");
}

function csvLine(fields: string[]): string {
  return fields.map((field) => `"${String(field || "").replaceAll("\"", "'")}"`).join(",");
}

function renderSummaryValue(value: unknown): string {
  if (value === null || value === undefined) {
    return "N/A";
  }
  if (typeof value === "number" || typeof value === "boolean") {
    return escapeHtml(String(value));
  }
  if (typeof value === "string") {
    return escapeHtml(value);
  }
  if (Array.isArray(value)) {
    if (value.length === 0) {
      return "[]";
    }
    return `<ul>${value.map((item) => `<li>${renderSummaryValue(item)}</li>`).join("")}</ul>`;
  }
  if (typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>);
    if (entries.length === 0) {
      return "{}";
    }
    const rows = entries
      .map(([entryKey, entryValue]) => `<tr><td>${escapeHtml(entryKey)}</td><td>${renderSummaryValue(entryValue)}</td></tr>`)
      .join("");
    return `<table><thead><tr><th>Key</th><th>Value</th></tr></thead><tbody>${rows}</tbody></table>`;
  }
  return escapeHtml(String(value));
}

function escapeHtml(value: string): string {
  return String(value || "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll("\"", "&quot;")
    .replaceAll("'", "&#39;");
}

function slugify(value: string): string {
  return value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 80);
}
