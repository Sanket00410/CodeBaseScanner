import { createWriteStream, existsSync, mkdirSync, readFileSync } from "node:fs";
import { promises as fs } from "node:fs";
import path from "node:path";

import PDFDocument from "pdfkit";

import {
  EnterpriseAssuranceSummary,
  DataQualitySummary,
  ExportRequest,
  ScanView,
  ToolExecutionEvidence,
  ToolchainExecutionSummary,
  ToolchainStatusEntry,
  VulnerabilityFinding,
  VulnerabilityFixedCodeReport,
} from "./types";

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

interface ExecutionEvidenceRow {
  tool: string;
  status: string;
  timestamp: string;
  command: string;
  exitCode: string;
  durationMs: number;
  stdoutHash: string;
  stderrHash: string;
  stdoutBytes: number;
  stderrBytes: number;
  stdoutPreview: string;
  stderrPreview: string;
}

interface ToolTimingRow {
  tool: string;
  status: string;
  attempted: boolean;
  durationMs: number;
  findingsCount: number;
  errorsCount: number;
  avgMsPerFinding: number | null;
}

function sanitizeExportToken(value: string, fallback: string): string {
  const normalized = String(value || "")
    .trim()
    .replaceAll("\\", "/")
    .replace(/^[A-Za-z]:/, "")
    .replace(/^\/+|\/+$/g, "");
  const token = normalized
    .replace(/[^A-Za-z0-9._-]+/g, "-")
    .replace(/-+/g, "-")
    .replace(/^[-_.]+|[-_.]+$/g, "");
  return token || fallback;
}

function extractExportTargetName(scan: ScanView): string {
  const candidates = [
    scan.report.vulnerability_fixed_code_report.target_path,
    scan.report.existing_implementation_report.target_path,
    scan.report.executive_summary.target_path,
  ]
    .map((item) => String(item || "").trim())
    .filter(Boolean);

  for (const candidate of candidates) {
    const normalized = candidate.replaceAll("\\", "/");
    if (/^https?:\/\//i.test(normalized)) {
      try {
        const url = new URL(normalized);
        const segments = url.pathname.split("/").filter(Boolean);
        return sanitizeExportToken(segments.at(-1) || url.hostname, "target");
      } catch {
        return sanitizeExportToken(normalized.split("/").filter(Boolean).at(-1) || normalized, "target");
      }
    }
    const segments = normalized.split("/").filter(Boolean);
    if (segments.length > 0) {
      return sanitizeExportToken(segments.at(-1) || normalized, "target");
    }
  }

  return "target";
}

function extractExportDateTimeParts(value: string): { datePart: string; timePart: string } {
  const raw = String(value || "").trim();
  const parsed = new Date(raw);
  if (!Number.isNaN(parsed.getTime())) {
    const datePart = [
      parsed.getFullYear(),
      String(parsed.getMonth() + 1).padStart(2, "0"),
      String(parsed.getDate()).padStart(2, "0"),
    ].join("-");
    const timePart = [
      String(parsed.getHours()).padStart(2, "0"),
      String(parsed.getMinutes()).padStart(2, "0"),
      String(parsed.getSeconds()).padStart(2, "0"),
      String(parsed.getMilliseconds()).padStart(3, "0"),
    ].join("-");
    return { datePart, timePart };
  }
  const safe = raw.replaceAll(":", "-").replaceAll(".", "-").replace("T", "_");
  const [datePartRaw, timePartRaw] = safe.split("_");
  return {
    datePart: sanitizeExportToken(datePartRaw || "date", "date"),
    timePart: sanitizeExportToken(timePartRaw || "time", "time"),
  };
}

function formatDisplayTimestamp(value: string): string {
  const raw = String(value || "").trim();
  const parsed = new Date(raw);
  if (Number.isNaN(parsed.getTime())) {
    return raw || "N/A";
  }
  return `${parsed.getFullYear()}-${String(parsed.getMonth() + 1).padStart(2, "0")}-${String(parsed.getDate()).padStart(2, "0")} ${String(parsed.getHours()).padStart(2, "0")}:${String(parsed.getMinutes()).padStart(2, "0")}:${String(parsed.getSeconds()).padStart(2, "0")}.${String(parsed.getMilliseconds()).padStart(3, "0")}`;
}

function exportReportTypeToken(
  reportType: ExportRequest["reportType"],
  reportStyle?: ExportRequest["reportStyle"],
): string {
  if (reportType === "vulnerability" && reportStyle) {
    return `vulnerability_${reportStyle}`;
  }
  return reportType;
}

function exportFormatExtension(format: ExportRequest["format"]): string {
  return format === "sarif" ? "sairf" : format;
}

function resolveReportGlobeTexturePath(): string | null {
  const candidates = [
    path.resolve(__dirname, "..", "..", "frontend", "public", "earth-night-texture.jpg"),
    path.resolve(process.cwd(), "frontend", "public", "earth-night-texture.jpg"),
  ];
  for (const candidate of candidates) {
    if (existsSync(candidate)) {
      return candidate;
    }
  }
  return null;
}

function loadReportGlobeTextureDataUri(): string {
  const texturePath = resolveReportGlobeTexturePath();
  if (!texturePath) {
    return "";
  }
  try {
    return `data:image/jpeg;base64,${readFileSync(texturePath).toString("base64")}`;
  } catch {
    return "";
  }
}

const REPORT_GLOBE_TEXTURE_PATH = resolveReportGlobeTexturePath();
const REPORT_GLOBE_TEXTURE_DATA_URI = loadReportGlobeTextureDataUri();

function resolveEnterpriseAssurance(
  scan: ScanView,
  summary: VulnerabilityFixedCodeReport["summary"],
): EnterpriseAssuranceSummary | null {
  const existing = summary.enterprise_assurance || scan.report.executive_summary.enterprise_assurance || null;
  const existingMeaningful =
    existing &&
    (Number(existing.required_tools_total || 0) > 0 ||
      Number(existing.readiness_score || 0) > 0 ||
      Boolean((existing.blockers || []).length) ||
      Number(existing.toolchain_attempted_tools || 0) > 0);
  if (existingMeaningful) {
    return existing;
  }
  const toolchainExecution = resolveToolchainExecution(scan, summary);
  const findings = scan.report.vulnerability_fixed_code_report.findings || [];
  const requiredTools = Object.entries(scan.report.vulnerability_fixed_code_report.toolchain_status || {})
    .filter(([, item]) => item.selected && item.runner_available !== false)
    .map(([tool]) => tool);
  const requiredToolsReady = requiredTools.filter(
    (tool) => scan.report.vulnerability_fixed_code_report.toolchain_status?.[tool]?.available,
  ).length;
  const requiredCoverage = requiredTools.length
    ? Math.round(((toolchainExecution?.attempted_tools || 0) / requiredTools.length) * 10000) / 100
    : 0;
  const failures = toolchainExecution?.failures || [];
  const criticalFindings = findings.filter((finding) => finding.severity === "Critical").length;
  const highFindings = findings.filter((finding) => finding.severity === "High").length;
  const blockers: string[] = [];
  if (criticalFindings > 0) {
    blockers.push(`${criticalFindings} critical finding(s) still require remediation before release.`);
  }
  for (const failure of failures.slice(0, 6)) {
    blockers.push(`${failure.tool}: ${failure.message}`);
  }
  if (!blockers.length && requiredTools.length && (toolchainExecution?.attempted_tools || 0) === 0) {
    blockers.push("Selected analyzers did not produce execution evidence for this scan.");
  }
  const successRate = Number(toolchainExecution?.success_rate_percent || 0);
  const readinessScore = Math.max(
    0,
    Math.min(100, Math.round(requiredCoverage * 0.45 + successRate * 0.35 + Math.max(0, 25 - criticalFindings * 7 - highFindings * 2) * 100) / 100),
  );
  const status = blockers.length ? "blocked" : requiredCoverage < 100 || successRate < 80 ? "warning" : "ready";
  return {
    status,
    is_enterprise_ready: status === "ready",
    scan_profile: String(summary.scan_profile || scan.report.executive_summary.scan_profile || "standard") as EnterpriseAssuranceSummary["scan_profile"],
    required_tools: requiredTools,
    required_tools_total: requiredTools.length,
    required_tools_ready: requiredToolsReady,
    required_tools_coverage_percent: requiredCoverage,
    recommended_tools: [],
    recommended_tools_total: 0,
    recommended_tools_ready: 0,
    recommended_tools_coverage_percent: 0,
    toolchain_success_rate_percent: successRate,
    toolchain_attempted_tools: Number(toolchainExecution?.attempted_tools || 0),
    toolchain_failed_tools: Number(toolchainExecution?.failed_tools || 0),
    toolchain_unavailable_tools: Number(toolchainExecution?.unavailable_tools || 0),
    toolchain_no_runner_tools: Number(toolchainExecution?.no_runner_tools || 0),
    readiness_score: readinessScore,
    blockers,
    advisories: [],
    recommendation:
      status === "blocked"
        ? "Resolve critical findings and failed analyzer coverage before using this export for release sign-off."
        : status === "warning"
          ? "Increase analyzer coverage and close high-priority risks before production deployment."
          : "Release criteria met with current analyzer coverage.",
  };
}

function resolveToolchainExecution(
  scan: ScanView,
  summary: VulnerabilityFixedCodeReport["summary"],
): ToolchainExecutionSummary | null {
  const existing = summary.toolchain_execution || scan.report.executive_summary.toolchain_execution || null;
  const existingMeaningful =
    existing &&
    (Number(existing.attempted_tools || 0) > 0 ||
      Number(existing.failed_tools || 0) > 0 ||
      Number(existing.unavailable_tools || 0) > 0 ||
      (Array.isArray(existing.timing_breakdown) && existing.timing_breakdown.length > 0));
  if (existingMeaningful) {
    return existing;
  }
  const toolchainStatus = scan.report.vulnerability_fixed_code_report.toolchain_status || {};
  const selectedEntries = Object.entries(toolchainStatus).filter(([, item]) => item.selected);
  if (!selectedEntries.length) {
    return null;
  }
  const statusDistribution: Record<string, number> = {};
  const failures: ToolchainExecutionSummary["failures"] = [];
  const slowestTools: ToolchainExecutionSummary["slowest_tools"] = [];
  const timingBreakdown: NonNullable<ToolchainExecutionSummary["timing_breakdown"]> = [];
  let attemptedTools = 0;
  let successfulTools = 0;
  let failedTools = 0;
  let unavailableTools = 0;
  let noRunnerTools = 0;
  let skippedTools = 0;
  let totalAttemptedDurationMs = 0;

  for (const [tool, item] of selectedEntries) {
    const execution = item.execution;
    const attempted = Boolean(execution?.attempted);
    const available = Boolean(item.available);
    const runnerAvailable = item.runner_available !== false;
    const findingsCount = Number(execution?.findings_count || 0);
    const errors = Array.isArray(execution?.errors) ? execution?.errors : [];
    const status =
      String(execution?.status || (!available ? "unavailable" : !runnerAvailable ? "no_runner" : attempted ? (errors.length ? "failed" : "success") : "skipped"));
    statusDistribution[status] = Number(statusDistribution[status] || 0) + 1;
    if (!available) unavailableTools += 1;
    if (!runnerAvailable) noRunnerTools += 1;
    if (attempted) {
      attemptedTools += 1;
      totalAttemptedDurationMs += Number(execution?.duration_ms || 0);
      if (status === "success" || status === "partial_success") {
        successfulTools += 1;
      } else {
        failedTools += 1;
      }
      slowestTools.push({
        tool,
        duration_ms: Number(execution?.duration_ms || 0),
        findings_count: findingsCount,
        status,
      });
    } else {
      skippedTools += 1;
    }
    if (status !== "success" && status !== "partial_success" && (attempted || !available || !runnerAvailable || errors.length)) {
      failures.push({
        tool,
        status,
        message: String(item.message || "Analyzer did not complete successfully."),
        errors: errors.map((entry) => String(entry)),
      });
    }
    timingBreakdown.push({
      tool,
      selected: true,
      available,
      runner_available: runnerAvailable,
      attempted,
      status,
      duration_ms: Number(execution?.duration_ms || 0),
      findings_count: findingsCount,
      errors_count: errors.length,
      avg_ms_per_finding: findingsCount ? Math.round((Number(execution?.duration_ms || 0) / findingsCount) * 100) / 100 : null,
    });
  }

  return {
    total_tools: Object.keys(toolchainStatus).length,
    selected_tools: selectedEntries.length,
    available_tools: selectedEntries.filter(([, item]) => item.available).length,
    integrated_tools: selectedEntries.filter(([, item]) => item.integrated).length,
    runner_available_tools: selectedEntries.filter(([, item]) => item.runner_available !== false).length,
    attempted_tools: attemptedTools,
    successful_tools: successfulTools,
    failed_tools: failedTools,
    unavailable_tools: unavailableTools,
    no_runner_tools: noRunnerTools,
    skipped_tools: skippedTools,
    success_rate_percent: attemptedTools ? Math.round((successfulTools / attemptedTools) * 10000) / 100 : 0,
    status_distribution: statusDistribution,
    failures: failures.slice(0, 12),
    slowest_tools: slowestTools.sort((a, b) => b.duration_ms - a.duration_ms).slice(0, 8),
    total_attempted_duration_ms: totalAttemptedDurationMs,
    average_attempted_duration_ms: attemptedTools ? Math.round((totalAttemptedDurationMs / attemptedTools) * 100) / 100 : 0,
    timing_breakdown: timingBreakdown,
  };
}

function deriveDataQuality(
  summary: VulnerabilityFixedCodeReport["summary"],
  execSummary: ScanView["report"]["executive_summary"],
  findings: VulnerabilityFinding[],
  toolchainExecution: ToolchainExecutionSummary | null,
): DataQualitySummary {
  const rawTotal =
    Number(summary.raw_findings_total ?? execSummary.total_vulnerabilities ?? findings.length) || 0;
  const dedupTotal =
    Number(summary.total_findings ?? execSummary.deduplicated_vulnerabilities ?? findings.length) || 0;
  const duplicateRemoved =
    Number(summary.duplicate_findings_removed) || Math.max(0, rawTotal - dedupTotal);
  const suppressionReport = (execSummary as unknown as { suppression_report?: { suppressed_count?: number } })
    .suppression_report;
  const suppressed = Number(summary.suppressed_by_policy ?? suppressionReport?.suppressed_count ?? 0) || 0;
  const suppressionRate =
    Math.round((suppressed / Math.max(1, dedupTotal + suppressed)) * 10000) / 100;
  const successRate = Number(toolchainExecution?.success_rate_percent ?? 0) || 0;
  const confidence = String(execSummary.assessment_confidence ?? "N/A");
  const confidenceLookup: Record<string, number> = { high: 85, medium: 65, low: 40 };
  const confidenceScore = confidenceLookup[confidence.toLowerCase()] ?? 55;

  let unknownRule = 0;
  let unknownCwe = 0;
  let unknownOwasp = 0;
  let unknownTaxonomy = 0;
  for (const finding of findings) {
    const ruleId = String(finding.rule_id ?? "").trim();
    const cwe = String((finding as { cwe_id?: string; cwe?: string }).cwe_id ?? (finding as { cwe?: string }).cwe ?? "").trim();
    const owasp = String((finding as { owasp_mapping?: string; owasp_category?: string }).owasp_mapping ?? (finding as { owasp_category?: string }).owasp_category ?? "").trim();
    if (!ruleId) unknownRule += 1;
    if (!cwe) unknownCwe += 1;
    if (!owasp) unknownOwasp += 1;
    if (!ruleId || !cwe || !owasp) unknownTaxonomy += 1;
  }

  return {
    raw_findings: rawTotal,
    deduplicated_findings: dedupTotal,
    duplicate_findings_removed: duplicateRemoved,
    dedup_ratio_percent: Math.round((duplicateRemoved / Math.max(1, rawTotal)) * 10000) / 100,
    suppressed_findings: suppressed,
    suppression_rate_percent: suppressionRate,
    tool_success_rate_percent: Math.round(successRate * 100) / 100,
    tool_attempted_count: Number(toolchainExecution?.attempted_tools ?? 0) || 0,
    coverage_confidence: confidence,
    coverage_confidence_score: Math.round(confidenceScore * 10) / 10,
    unknown_rule_count: unknownRule,
    unknown_cwe_count: unknownCwe,
    unknown_owasp_count: unknownOwasp,
    unknown_taxonomy_count: unknownTaxonomy,
  };
}

function summarizeTimingRows(rows: ToolTimingRow[]) {
  const attempted = rows.filter((row) => row.attempted);
  const visible = [...attempted].sort((left, right) => right.durationMs - left.durationMs);
  const omitted = 0;
  const totalDuration = attempted.reduce((sum, row) => sum + row.durationMs, 0);
  const averageDuration = attempted.length ? Number((totalDuration / attempted.length).toFixed(2)) : 0;
  return { attempted, visible, omitted, totalDuration, averageDuration };
}

const SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"];
const SEVERITY_TO_SARIF: Record<string, string> = {
  Critical: "error",
  High: "error",
  Medium: "warning",
  Low: "note",
  Info: "note",
};

function loadDashboardAsset(name: string): string {
  return loadTextAssetFromCandidates([
    path.resolve(process.cwd(), "report-dashboard", name),
    path.resolve(__dirname, "..", "..", "report-dashboard", name),
    path.resolve(__dirname, "..", "report-dashboard", name),
  ]);
}

function loadNodeAsset(...segments: string[]): string {
  return loadTextAssetFromCandidates([
    path.resolve(process.cwd(), "node_modules", ...segments),
    path.resolve(__dirname, "..", "..", "node_modules", ...segments),
    path.resolve(__dirname, "..", "node_modules", ...segments),
  ]);
}

function tryLoadNodeAsset(...segments: string[]): string | null {
  try {
    return loadNodeAsset(...segments);
  } catch (_error) {
    return null;
  }
}

function loadTextAssetFromCandidates(candidates: string[]): string {
  for (const candidate of candidates) {
    if (existsSync(candidate)) {
      const content = readFileSync(candidate, "utf-8");
      return content.charCodeAt(0) === 0xfeff ? content.slice(1) : content;
    }
  }
  throw new Error(`Asset not found. Candidates: ${candidates.join(", ")}`);
}

function escapeInlineJson(value: unknown): string {
  return JSON.stringify(value)
    .replaceAll("</script", "<\\/script")
    .replaceAll("<!--", "<\\!--");
}

export class ExportService {
  constructor(private readonly outputDir: string) {
    mkdirSync(this.outputDir, { recursive: true });
  }

  resolveOutputPath(
    scan: ScanView,
    reportType: ExportRequest["reportType"],
    format: ExportRequest["format"],
    reportStyle?: ExportRequest["reportStyle"],
  ): string {
    const timestampSource =
      scan.completedAt ||
      scan.report.vulnerability_fixed_code_report.generated_at ||
      scan.report.existing_implementation_report.generated_at ||
      scan.report.executive_summary.generated_at ||
      "";
    const { datePart, timePart } = extractExportDateTimeParts(timestampSource);
    const typeToken = sanitizeExportToken(exportReportTypeToken(reportType, reportStyle), "report");
    const targetToken = extractExportTargetName(scan);
    const extension = exportFormatExtension(format);
    const fileName = `${datePart}_${timePart}_${typeToken}_${targetToken}.${extension}`;
    return path.join(this.outputDir, fileName);
  }

  renderReportHtml(
    scan: ScanView,
    reportType: ExportRequest["reportType"],
    reportStyle?: ExportRequest["reportStyle"],
  ): string {
    return this.toHtml(scan, reportType, reportStyle);
  }

  async exportReport(scan: ScanView, request: ExportRequest): Promise<string> {
    const destination = this.resolveOutputPath(scan, request.reportType, request.format, request.reportStyle);

    if (request.format === "json") {
      await fs.writeFile(destination, JSON.stringify(this.selectPayload(scan, request.reportType), null, 2), "utf-8");
      return destination;
    }
    if (request.format === "xml") {
      await fs.writeFile(destination, this.toXml(scan, request.reportType), "utf-8");
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
      await fs.writeFile(destination, this.toHtml(scan, request.reportType, request.reportStyle), "utf-8");
      return destination;
    }
    if (request.format === "sarif") {
      if (request.reportType === "existing" || request.reportType === "fixes" || request.reportType === "finding_details") {
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
        false_positive_report: scan.report.false_positive_report || scan.report.vulnerability_fixed_code_report.false_positive_report,
        role_aware_report: scan.report.role_aware_report || scan.report.vulnerability_fixed_code_report.role_aware_report,
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
          summary: scan.report.vulnerability_fixed_code_report.summary,
          findings: sortedFindings(scan.report.vulnerability_fixed_code_report.findings || []).map((item) => ({
            finding_uid: item.finding_uid,
            severity: item.severity,
            cvss_score: item.cvss_score,
            vulnerability_title: normalizedFindingTitle(item),
            file_path: normalizePath(item.file_path),
            line_number: item.line_number || 1,
            cwe_id: item.cwe_id || "N/A",
            owasp_mapping: item.owasp_mapping || "N/A",
            cve_ids: item.cve_ids || [],
            advisory_ids: item.advisory_ids || [],
            dependency_name: item.dependency_name,
            dependency_version: item.dependency_version,
            dependency_id: item.dependency_id,
            recommendation: item.recommendation || "",
            original_code: item.original_code || "",
            suggested_fix: item.fixed_code || "",
            fixed_code: item.fixed_code || "",
            fix_artifact_kind: item.fix_artifact_kind,
            fix_artifact_label: item.fix_artifact_label,
            patch_preview: item.patch_preview || "",
            active_poc: item.active_poc,
            fix_verification: item.fix_verification,
            ai_remediation_summary: item.ai_remediation_summary,
            ai_validation_steps: item.ai_validation_steps,
            ai_fix_source: item.ai_fix_source,
            ai_fix_confidence_label: item.ai_fix_confidence_label,
            ai_fix_confidence_score: item.ai_fix_confidence_score,
            ai_fix_grounded: item.ai_fix_grounded,
            ai_grounding_notes: item.ai_grounding_notes,
            evidence_replay_pack: item.evidence_replay_pack,
          })),
        },
      };
    }
    if (reportType === "finding_details") {
      const findings = sortedFindings(scan.report.vulnerability_fixed_code_report.findings || []);
      return {
        scanner: scan.report.scanner,
        executive_summary: scan.report.executive_summary,
        finding_details_report: {
          title: "CodeSentinelX Finding Details Report",
          target_path: scan.report.vulnerability_fixed_code_report.target_path,
          generated_at: scan.report.vulnerability_fixed_code_report.generated_at,
          total_findings: findings.length,
          rows: findings.map((item) => ({
            finding_details: normalizedFindingTitle(item),
            severity: item.severity,
            location: `${normalizePath(item.file_path)}:${item.line_number || 1}`,
            issue_description: item.description || item.business_impact || "",
            remediation: preferredFindingFix(item),
            cwe: item.cwe_id || "N/A",
            owasp: item.owasp_mapping || "N/A",
            cvss_score: item.cvss_score || 0,
            rule_id: item.rule_id || "",
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
          normalizedFindingTitle(item),
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

    if (reportType === "finding_details") {
      const findings = sortedFindings(scan.report.vulnerability_fixed_code_report.findings || []);
      const header = "FindingDetails,Severity,Location,IssueDescription,Remediation\n";
      const rows = findings.map((item) =>
        csvLine([
          normalizedFindingTitle(item),
          item.severity,
          `${normalizePath(item.file_path)}:${String(item.line_number || 1)}`,
          singleLine(item.description || item.business_impact || ""),
          singleLine(preferredFindingFix(item)),
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
        normalizedFindingTitle(item),
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

  private toHtml(
    scan: ScanView,
    reportType: ExportRequest["reportType"],
    reportStyle?: ExportRequest["reportStyle"],
  ): string {
    if (reportType === "existing") {
      return renderExistingHtml(scan);
    }
    if (reportType === "vulnerability") {
      return reportStyle === "modern" ? this.renderModernVulnerabilityDashboard(scan) : renderVulnerabilityHtml(scan);
    }
    if (reportType === "fixes") {
      return renderFixesHtml(scan);
    }
    if (reportType === "finding_details") {
      return renderFindingDetailsHtml(scan);
    }
    return renderCombinedHtml(scan);
  }

  private renderModernVulnerabilityDashboard(scan: ScanView): string {
    const payload = this.selectPayload(scan, "vulnerability");
    const template = loadDashboardAsset("index.html");
    const css = loadDashboardAsset("styles.css");
    const js = loadDashboardAsset("app.js");
    const vendorCssParts = [
      tryLoadNodeAsset("datatables.net-dt", "css", "dataTables.dataTables.min.css"),
      tryLoadNodeAsset("prismjs", "themes", "prism-tomorrow.min.css"),
    ].filter((item): item is string => Boolean(item));
    const vendorJsParts = [
      tryLoadNodeAsset("jquery", "dist", "jquery.min.js"),
      tryLoadNodeAsset("datatables.net", "js", "dataTables.min.js"),
      tryLoadNodeAsset("chart.js", "dist", "chart.umd.js"),
      tryLoadNodeAsset("prismjs", "prism.js"),
      tryLoadNodeAsset("prismjs", "components", "prism-python.min.js"),
      tryLoadNodeAsset("prismjs", "components", "prism-javascript.min.js"),
      tryLoadNodeAsset("prismjs", "components", "prism-java.min.js"),
    ].filter((item): item is string => Boolean(item));
    const vendorCss = vendorCssParts.join("\n");
    const vendorJs = vendorJsParts.join("\n;\n");
    const cdnFallbackHead = `
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/datatables.net-dt@2.1.8/css/dataTables.dataTables.min.css" />
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/prismjs@1.29.0/themes/prism-tomorrow.min.css" />`.trim();
    const cdnFallbackBody = `
<script src="https://cdn.jsdelivr.net/npm/jquery@3.7.1/dist/jquery.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/datatables.net@2.1.8/js/dataTables.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.7/dist/chart.umd.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/prismjs@1.29.0/prism.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/prismjs@1.29.0/components/prism-python.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/prismjs@1.29.0/components/prism-javascript.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/prismjs@1.29.0/components/prism-java.min.js"></script>`.trim();

    return template.replace(
      "</head>",
      `${vendorCss ? `<style>\n${vendorCss}\n</style>` : cdnFallbackHead}\n<style>\n${css}\n</style>\n</head>`,
    ).replace(
      "</body>",
      `${vendorJs ? `<script>\n${vendorJs}\n</script>` : cdnFallbackBody}\n<script>window.__REPORT_DATA__ = ${escapeInlineJson(payload)};</script>\n<script>\n${js}\n</script>\n</body>`,
    );
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
          shortDescription: { text: normalizedFindingTitle(finding) || "Security finding" },
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
        message: { text: normalizedFindingTitle(finding) || "Security finding" },
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

  private toXml(scan: ScanView, reportType: ExportRequest["reportType"]): string {
    const payload = this.selectPayload(scan, reportType);
    const body = objectToXml("payload", payload);
    return `<?xml version="1.0" encoding="UTF-8"?>\n<codesentinelx_report>${body}</codesentinelx_report>\n`;
  }

  private async writePdf(scan: ScanView, outputPath: string, reportType: ExportRequest["reportType"]): Promise<void> {
    await new Promise<void>((resolve, reject) => {
      const doc = new PDFDocument({ margin: 32, size: "A4" });
      const stream = createWriteStream(outputPath);
      doc.pipe(stream);
      stream.on("finish", resolve);
      stream.on("error", reject);
      doc.on("error", reject);
      const applyBackdrop = () => {
        drawPdfReportBackdrop(doc);
      };
      doc.on("pageAdded", applyBackdrop);
      applyBackdrop();

      if (reportType === "existing") {
        writeExistingPdf(doc, scan);
      } else if (reportType === "vulnerability") {
        writeVulnerabilityPdf(doc, scan);
      } else if (reportType === "fixes") {
        writeFixesPdf(doc, scan);
      } else if (reportType === "finding_details") {
        writeFindingDetailsPdf(doc, scan);
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
  writePdfHero(doc, "CodeSentinelX Existing Security Implementation Report", [
    `Target: ${report.target_path}`,
    `Generated: ${formatDisplayTimestamp(report.generated_at)}`,
    `Profile: ${profileCompliance?.scan_profile_label || "Codebase"}`,
  ]);
  writePdfMetricStrip(doc, [
    { label: "Implemented Controls", value: String(summary.implemented_controls || 0), tone: "accent" },
    { label: "Security Domains", value: String(Object.keys(summary.category_distribution || {}).length), tone: "low" },
    { label: "Standards Mapped", value: String(Object.keys(summary.standards_coverage || {}).length), tone: "info" },
  ]);
  writePdfSectionHeader(doc, "Coverage Summary");
  writePdfKeyValueTable(doc, [
    { key: "Implemented Controls", value: String(summary.implemented_controls || 0) },
    { key: "Security Categories", value: String(Object.keys(summary.category_distribution || {}).length) },
    { key: "Coverage Levels", value: String(Object.keys(summary.coverage_levels || {}).length) },
    { key: "Standards Covered", value: String(Object.keys(summary.standards_coverage || {}).length) },
  ]);
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
    writePdfSectionHeader(doc, "Profile-Based OWASP / ASVS / WSTG Coverage");
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
    writeWrapped(doc, "Reference: OWASP Top 10 latest official published release is 2021.", 8);
    for (const framework of profileCompliance.frameworks || []) {
      writeWrapped(
        doc,
        `- ${framework.label} | applicable=${framework.applicable ? "yes" : "no"} | covered=${framework.summary.covered}, gap=${framework.summary.gap}, n/a=${framework.summary.not_applicable}`,
        8,
      );
      for (const row of (framework.rows || []).slice(0, 30)) {
        const rowAny = row as unknown as Record<string, unknown>;
        const rowId = String(rowAny.id ?? rowAny.item_id ?? rowAny.key ?? "N/A");
        const rowTitle = String(rowAny.title ?? rowAny.category ?? rowAny.name ?? rowAny.label ?? "Unlabeled");
        const rowStatus = String(rowAny.status ?? rowAny.coverage_status ?? "gap");
        const rowFindings = Number(rowAny.finding_count ?? rowAny.findings ?? 0);
        const rowControls = Number(rowAny.control_count ?? rowAny.controls ?? 0);
        writeWrapped(
          doc,
          `    ${rowId && rowId !== "undefined" ? rowId : "N/A"} ${rowTitle && rowTitle !== "undefined" ? rowTitle : "Unlabeled"} -> ${rowStatus && rowStatus !== "undefined" ? rowStatus : "gap"} (findings=${Number.isFinite(rowFindings) ? rowFindings : 0}, controls=${Number.isFinite(rowControls) ? rowControls : 0})`,
          8,
        );
      }
      if ((framework.rows || []).length > 30) {
        writeWrapped(doc, `    ... ${framework.rows.length - 30} additional rows not shown.`, 8);
      }
    }
  }

  writePdfSectionHeader(doc, "Implemented Controls");

  for (const control of report.controls.slice(0, 120)) {
    writeWrapped(doc, `- ${control.name} (${control.category}) [${control.coverage_level}]`, 9);
  }

  const controlEvidenceRows = report.controls.flatMap((control) => {
    const evidence = Array.isArray((control as { evidence?: Array<Record<string, unknown>> }).evidence)
      ? ((control as { evidence?: Array<Record<string, unknown>> }).evidence || [])
      : [];
    return evidence.slice(0, 6).map((entry) => ({
      control: control.name,
      file: normalizePath(String(entry.file_path || "N/A")),
      line: Number(entry.line_number || 1),
      snippet: String(entry.snippet || "").trim(),
    }));
  });
  writePdfSectionHeader(doc, "Control Evidence (File/Line)");
  if (!controlEvidenceRows.length) {
    writeWrapped(doc, "- No control-level evidence captured.", 9);
  } else {
    for (const row of controlEvidenceRows.slice(0, 80)) {
      writeWrapped(doc, `- ${row.control} | ${row.file}:${row.line}`, 8);
      writeWrapped(doc, `  evidence: ${singleLine(row.snippet || "N/A")}`, 8);
    }
    if (controlEvidenceRows.length > 80) {
      writeWrapped(doc, `... ${controlEvidenceRows.length - 80} additional evidence row(s) omitted in PDF.`, 8);
    }
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
  const enterprise = resolveEnterpriseAssurance(scan, report.summary);
  const toolchainExecution = resolveToolchainExecution(scan, report.summary);
  const dataQualityRaw = report.summary.data_quality || scan.report.executive_summary.data_quality || null;
  const dataQuality =
    dataQualityRaw && Object.keys(dataQualityRaw).length > 0
      ? dataQualityRaw
      : deriveDataQuality(report.summary, scan.report.executive_summary, findings, toolchainExecution);
  const timingBreakdown = collectToolTimingRows(report.toolchain_status || {}, toolchainExecution);
  const timingSummary = summarizeTimingRows(timingBreakdown);
  const executionEvidence = collectExecutionEvidenceRows(report.toolchain_status || {});
  const roleAware = report.role_aware_report || scan.report.role_aware_report || {};
  const falsePositiveReport =
    report.false_positive_report ||
    scan.report.false_positive_report ||
    (roleAware.false_positive_report as Record<string, unknown>) ||
    {};
  const summaryExtras = report.summary as VulnerabilityFixedCodeReport["summary"] & {
    release_gate_distribution?: Record<string, number>;
    risk_intelligence?: { findings_with_cve?: number; findings_cvss_ge_7?: number; known_exploited_findings?: number };
    auth_abuse_session_security?: {
      total_findings?: number;
      severity_distribution?: Record<string, number>;
      top_vulnerability_types?: Array<{ type: string; count: number }>;
    };
    deterministic_replay?: {
      enabled?: boolean;
      mode?: string;
      findings_total?: number;
      findings_with_replay?: number;
      findings_without_replay?: number;
      replay_coverage_percent?: number;
      tool_evidence_records?: number;
      tools_with_evidence?: string[];
      tool_mismatch_counts?: Record<string, number>;
      record_hashes?: string[];
    };
    report_integrity_chain?: {
      chain_version?: string;
      tamper_evident?: boolean;
      generated_at?: string;
      metadata_sha256?: string;
      findings_sha256?: string;
      tool_evidence_sha256?: string;
      report_sha256?: string;
      previous_report_sha256?: string | null;
    };
  };
  const riskIntel = resolveRiskIntelligence(summaryExtras, findings);
  const releaseGateDistribution: Record<string, number> = summaryExtras.release_gate_distribution || {};
  const authAbuse = resolveAuthAbuse(summaryExtras, findings);
  const deterministicReplay =
    summaryExtras.deterministic_replay ||
    (report as VulnerabilityFixedCodeReport & { deterministic_replay?: NonNullable<typeof summaryExtras.deterministic_replay> }).deterministic_replay ||
    scan.report.executive_summary.deterministic_replay ||
    null;
  const reportIntegrity =
    summaryExtras.report_integrity_chain ||
    (report as VulnerabilityFixedCodeReport & { report_integrity_chain?: NonNullable<typeof summaryExtras.report_integrity_chain> }).report_integrity_chain ||
    scan.report.executive_summary.report_integrity_chain ||
    null;
  const roleAwareRecord = roleAware as unknown as Record<string, unknown>;
  const ctoBoard = resolveCtoBoardView(roleAwareRecord, findings, report.summary, riskIntel);
  const advanced = resolveAdvancedFeatures(roleAwareRecord, findings, enterprise, dataQuality);
  const hasRiskIntelligence = hasRiskIntelligenceData(riskIntel, releaseGateDistribution);
  const hasFalsePositiveData = hasFalsePositiveCandidates(falsePositiveReport);
  const urgentRisks = Array.isArray(ctoBoard.top_5_urgent_risks) ? ctoBoard.top_5_urgent_risks : [];
  const aiExecutiveSummary = Array.isArray(ctoBoard.ai_summary_plain_language) ? ctoBoard.ai_summary_plain_language : [];
  const ctoFinancialText = formatBestLikelyWorst((ctoBoard.financial_exposure_usd as Record<string, unknown>) || {});
  const ctoDowntimeText = formatBestLikelyWorst((ctoBoard.downtime_estimate as Record<string, unknown>) || {});
  const hasEnterpriseData = Boolean(
    enterprise &&
      (Number(enterprise.required_tools_total || 0) > 0 ||
        Number(enterprise.readiness_score || 0) > 0 ||
        Boolean((enterprise.blockers || []).length) ||
        Number(toolchainExecution?.attempted_tools || 0) > 0),
  );
  const hasCtoData = Boolean(urgentRisks.length || aiExecutiveSummary.length || ctoFinancialText !== "N/A" || ctoDowntimeText !== "N/A");
  const aiSolutionEngine = (advanced.ai_solution_engine as Record<string, unknown>) || {};
  const fixWindowPlan =
    Object.keys((advanced.what_should_i_fix_first_ai as Record<string, unknown>) || {}).length > 0
      ? ((advanced.what_should_i_fix_first_ai as Record<string, unknown>) || {})
      : buildFallbackFixWindowPlan(findings);
  const hasMeaningfulFixPlan = Object.values(fixWindowPlan).some((value) => Array.isArray(value) && value.length > 0);
  const maturityMetrics = (advanced.security_maturity_scoring as Record<string, unknown>) || {};
  const hasMaturityData = Object.values(maturityMetrics).some((value) => Number(value) > 0);
  const hasAdvancedData = Boolean(hasMaturityData || hasMeaningfulFixPlan);
  const hasToolEvidenceData = executionEvidence.length > 0;
  const hasTimingData = timingSummary.visible.length > 0;
  const hasAuthAbuseData = hasMeaningfulAuthAbuse(authAbuse);
  const hasReplayData = hasReplaySummaryData(deterministicReplay);
  const hasIntegrityData = hasIntegrityChainData(reportIntegrity);

  writePdfHero(doc, "CodeSentinelX Vulnerability Report", [
    `Target: ${report.target_path}`,
    `Generated: ${formatDisplayTimestamp(report.generated_at)}`,
    `Risk Score: ${report.summary.risk_score} (${report.summary.risk_rating})`,
  ]);
  writePdfMetricStrip(doc, [
    { label: "Total Findings", value: String(report.summary.total_findings || findings.length), tone: "accent" },
    { label: "Critical", value: String(report.summary.severity_distribution?.Critical || 0), tone: "critical" },
    { label: "High", value: String(report.summary.severity_distribution?.High || 0), tone: "high" },
  ]);
  writePdfSectionHeader(doc, "Summary of Alerts");
  for (const severity of SEVERITY_ORDER) {
    const count = report.summary.severity_distribution?.[severity] || 0;
    writeWrapped(doc, `- ${severity}: ${count}`, 10);
  }

  writePdfSectionHeader(doc, "Top Affected Files");
  for (const item of fileAgg.slice(0, 25)) {
    writeWrapped(
      doc,
      `- ${item.file}: ${item.total} total (${item.counts.Critical || 0} critical, ${item.counts.High || 0} high)`,
      9,
    );
  }

  writePdfSectionHeader(doc, "Top OWASP Categories");
  for (const item of owaspAgg.slice(0, 12)) {
    writeWrapped(doc, `- ${item.owasp_category}: ${item.count}`, 9);
  }

  writePdfSectionHeader(doc, "Affected Modules");
  for (const item of moduleAgg.slice(0, 20)) {
    writeWrapped(
      doc,
      `- ${String(item.module)}: ${String(item.count)} total (${String(item.critical)} critical, ${String(item.high)} high)`,
      9,
    );
  }

  writePdfSectionHeader(doc, "Action Plan");
  for (const step of actionPlan.slice(0, 10)) {
    writeWrapped(doc, `- ${step}`, 9);
  }

  writePdfSectionHeader(doc, "Risk Intelligence and Release Gates");
  if (!hasRiskIntelligence) {
    writeWrapped(doc, "No risk-intelligence or release-gate artifacts were captured for this scan.", 9);
  } else {
    writePdfKeyValueTable(doc, [
      { key: "Findings with CVE", value: String(riskIntel ? riskIntel.findings_with_cve : 0) },
      { key: "Findings with CVSS >= 7.0", value: String(riskIntel ? riskIntel.findings_cvss_ge_7 : 0) },
      { key: "Known Exploited Findings (CISA KEV)", value: String(riskIntel ? riskIntel.known_exploited_findings : 0) },
      { key: "Release Gate: Block release", value: String(Number(releaseGateDistribution["Block release"] || 0)) },
      { key: "Release Gate: Fix before prod", value: String(Number(releaseGateDistribution["Fix before prod"] || 0)) },
      { key: "Release Gate: Scheduled fix", value: String(Number(releaseGateDistribution["Scheduled fix"] || 0)) },
      { key: "Release Gate: Track", value: String(Number(releaseGateDistribution["Track"] || 0)) },
    ]);
  }

  if (hasEnterpriseData) {
    writePdfSectionHeader(doc, "Enterprise Assurance");
    writePdfKeyValueTable(doc, [
      { key: "Status", value: String((enterprise?.status || "blocked").toUpperCase()) },
      { key: "Readiness Score", value: String(enterprise?.readiness_score ?? 0) },
      {
        key: "Required Tool Coverage",
        value: `${enterprise?.required_tools_ready ?? 0}/${enterprise?.required_tools_total ?? 0} (${(
          enterprise?.required_tools_coverage_percent ?? 0
        ).toFixed(2)}%)`,
      },
      {
        key: "Tool Execution Success",
        value: `${toolchainExecution?.successful_tools ?? 0}/${toolchainExecution?.attempted_tools ?? 0} (${(
          toolchainExecution?.success_rate_percent ?? 0
        ).toFixed(2)}%)`,
      },
      { key: "Failed Tools", value: String(toolchainExecution?.failed_tools ?? 0) },
      { key: "Recommendation", value: String(enterprise?.recommendation || "N/A") },
    ]);
    writeWrapped(doc, "Status meaning: READY=gate passed, WARNING=partial coverage, BLOCKED=release blockers present.", 8);
    for (const blocker of (enterprise?.blockers || []).slice(0, 10)) {
      writeWrapped(doc, `- ${blocker}`, 8);
    }
  }

  writePdfSectionHeader(doc, "Data Quality");
  writePdfKeyValueTable(doc, [
    { key: "Raw Findings", value: String(dataQuality.raw_findings ?? 0) },
    { key: "Deduplicated Findings", value: String(dataQuality.deduplicated_findings ?? 0) },
    { key: "Duplicates Removed", value: `${dataQuality.duplicate_findings_removed ?? 0} (${(dataQuality.dedup_ratio_percent ?? 0).toFixed(2)}%)` },
    { key: "Suppressed Findings", value: `${dataQuality.suppressed_findings ?? 0} (${(dataQuality.suppression_rate_percent ?? 0).toFixed(2)}%)` },
    { key: "Tool Success Rate", value: `${(dataQuality.tool_success_rate_percent ?? 0).toFixed(2)}%` },
    { key: "Coverage Confidence", value: `${String(dataQuality.coverage_confidence || "N/A")} (${(dataQuality.coverage_confidence_score ?? 0).toFixed(1)})` },
    { key: "Unknown Rule IDs", value: String(dataQuality.unknown_rule_count ?? 0) },
    { key: "Unknown CWE", value: String(dataQuality.unknown_cwe_count ?? 0) },
    { key: "Unknown OWASP", value: String(dataQuality.unknown_owasp_count ?? 0) },
    { key: "Taxonomy Gaps", value: String(dataQuality.unknown_taxonomy_count ?? 0) },
  ]);

  if (hasTimingData) {
    writePdfSectionHeader(doc, "Analyzer Runtime Breakdown");
    const totalDuration = timingSummary.totalDuration;
    const averageDuration = Math.round(timingSummary.averageDuration);
    writeWrapped(
      doc,
      `Attempted analyzers=${timingSummary.attempted.length}, total_duration=${totalDuration}ms, average_duration=${averageDuration}ms`,
      9,
    );
    if (timingSummary.omitted > 0) {
      writeWrapped(doc, `Omitted ${timingSummary.omitted} analyzer(s) that were unavailable or failed.`, 8);
    }
    for (const row of timingSummary.visible.slice(0, 12)) {
      writeWrapped(
        doc,
        `- ${row.tool}: status=${row.status}, attempted=${row.attempted ? "yes" : "no"}, duration=${row.durationMs}ms, findings=${row.findingsCount}`,
        8,
      );
    }
    if (timingSummary.visible.length > 12) {
      writeWrapped(doc, `... ${timingSummary.visible.length - 12} additional analyzer timing row(s) omitted in PDF.`, 8);
    }
  }

  if (hasCtoData) {
    writePdfSectionHeader(doc, "CTO / Board View");
    writeWrapped(
      doc,
      `Business Risk Exposure: ${Number(ctoBoard.business_risk_exposure_score || report.summary.risk_score || 0).toFixed(2)} / 100`,
      9,
    );
    const trendMeta = (ctoBoard.trend as Record<string, unknown>) || {};
    const trendText =
      trendMeta.available === false
        ? "Unavailable (no prior scan in report chain)"
        : `${String(trendMeta.direction || "stable")} (delta=${String(trendMeta.delta_points || 0)})`;
    writeWrapped(doc, `Trend: ${trendText}`, 9);
    if (ctoFinancialText !== "N/A") {
      writeWrapped(doc, `Financial Exposure USD (best/likely/worst): ${ctoFinancialText}`, 8);
    }
    if (ctoDowntimeText !== "N/A") {
      writeWrapped(doc, `Downtime estimate hours (best/likely/worst): ${ctoDowntimeText}`, 8);
    }
    for (const item of urgentRisks.slice(0, 5)) {
      const row = item as Record<string, unknown>;
      writeWrapped(
        doc,
        `- ${String(row.title || row.vulnerability_title || "Risk")} [${String(row.severity || "N/A")}] priority=${String(row.priority_score || "N/A")}`,
        8,
      );
    }
  }

  if (hasAdvancedData) {
    writePdfSectionHeader(doc, "AI Solution Engine");
    writeWrapped(
      doc,
      String(
        aiSolutionEngine.description || "Evidence-driven local remediation engine using finding context, code location, and validation evidence.",
      ),
      8,
    );
    writeWrapped(
      doc,
      `Mode=${String(aiSolutionEngine.mode || "contextual-remediation")} | Provider=${String(aiSolutionEngine.provider || "local-evidence-driven")} | Model=${String(aiSolutionEngine.model || "N/A")} | Status=${String(aiSolutionEngine.status || "ready")} | Grounded=${aiSolutionEngine.grounded_generation === false ? "No" : "Yes"} | Prioritization=${String(aiSolutionEngine.prioritization_status || "deterministic")}`,
      8,
    );
    writeWrapped(doc, "What Should I Fix First (AI):", 8);
    for (const [window, values] of Object.entries(fixWindowPlan).slice(0, 3)) {
      writeWrapped(doc, `- ${String(window).replaceAll("_", " ")}`, 8);
      if (!Array.isArray(values) || values.length === 0) {
        continue;
      }
      for (const rawEntry of values.slice(0, 3)) {
        if (!rawEntry || typeof rawEntry !== "object") {
          continue;
        }
        const entry = rawEntry as Record<string, unknown>;
        writeWrapped(
          doc,
          `  * ${String(entry.title || "Issue")} [${String(entry.severity || "Info")}] ${String(entry.file_path || "unknown")}:${Number(entry.line_number || 1)} | priority=${Number(entry.priority_score || 0).toFixed(2)} | fix_confidence=${String(entry.fix_confidence_label || "Medium")} (${Number(entry.fix_confidence_score || 0).toFixed(2)})`,
          8,
        );
      }
    }
  }

  if (hasToolEvidenceData) {
    writePdfSectionHeader(doc, "Tool Command Evidence (Authenticity)");
    for (const row of executionEvidence.slice(0, 18)) {
      writeWrapped(
        doc,
        `- [${row.tool}] ${row.command || "N/A"} | exit=${row.exitCode} | duration=${row.durationMs}ms | status=${row.status}`,
        8,
      );
      writeWrapped(
        doc,
        `  stdout_sha256=${row.stdoutHash || "N/A"} | stderr_sha256=${row.stderrHash || "N/A"} | stdout_bytes=${row.stdoutBytes} | stderr_bytes=${row.stderrBytes}`,
        8,
      );
    }
    if (executionEvidence.length > 18) {
      writeWrapped(doc, `... ${executionEvidence.length - 18} additional evidence row(s) omitted in PDF.`, 8);
    }
  }

  if (hasReplayData) {
    writePdfSectionHeader(doc, "Deterministic Evidence Replay Pack");
    const replayData = deterministicReplay as NonNullable<typeof deterministicReplay>;
    writePdfKeyValueTable(doc, [
      { key: "Mode", value: String(replayData.mode || "deterministic-evidence-replay") },
      { key: "Replay Coverage", value: `${Number(replayData.replay_coverage_percent || 0).toFixed(2)}%` },
      {
        key: "Findings with Replay",
        value: `${Number(replayData.findings_with_replay || 0)}/${Number(replayData.findings_total || 0)}`,
      },
      { key: "Evidence Records", value: String(Number(replayData.tool_evidence_records || 0)) },
      {
        key: "Tools with Evidence",
        value: Array.isArray(replayData.tools_with_evidence) && replayData.tools_with_evidence.length
          ? replayData.tools_with_evidence.join(", ")
          : "N/A",
      },
    ]);
  }

  if (hasIntegrityData) {
    writePdfSectionHeader(doc, "Tamper-Evident Report Chain");
    const integrityData = reportIntegrity as NonNullable<typeof reportIntegrity>;
    writePdfKeyValueTable(doc, [
      { key: "Chain Version", value: String(integrityData.chain_version || "1.0") },
      { key: "Tamper Evident", value: integrityData.tamper_evident ? "Yes" : "No" },
      { key: "Generated At", value: String(integrityData.generated_at || "N/A") },
      { key: "Report SHA256", value: String(integrityData.report_sha256 || "N/A") },
      { key: "Findings SHA256", value: String(integrityData.findings_sha256 || "N/A") },
      { key: "Tool Evidence SHA256", value: String(integrityData.tool_evidence_sha256 || "N/A") },
      { key: "Metadata SHA256", value: String(integrityData.metadata_sha256 || "N/A") },
      { key: "Previous Report SHA256", value: String(integrityData.previous_report_sha256 || "N/A") },
    ]);
  }

  if (hasAuthAbuseData) {
    const authAbuseData = authAbuse as NonNullable<typeof authAbuse>;
    writePdfSectionHeader(doc, "Auth Abuse & Session Security");
    writeWrapped(
      doc,
      `Total=${Number(authAbuseData.total_findings || 0)} | Critical=${Number(authAbuseData.severity_distribution?.Critical || 0)} | High=${Number(authAbuseData.severity_distribution?.High || 0)}`,
      9,
    );
    for (const item of (authAbuseData.top_vulnerability_types || []).slice(0, 8)) {
      writeWrapped(doc, `- ${item.type}: ${item.count}`, 8);
    }
    for (const item of (authAbuseData.issue_file_mapping || []).slice(0, 10)) {
      writeWrapped(
        doc,
        `- ${String(item.issue_type || "Issue")} -> ${String(item.file || "unknown")} (${Number(item.count || 0)} total, ${Number(item.critical || 0)} critical, ${Number(item.high || 0)} high)`,
        8,
      );
    }
  }

  if (hasFalsePositiveData) {
    writePdfSectionHeader(doc, "False Positive Review");
    writeWrapped(
      doc,
      `Policy: ${String((falsePositiveReport as Record<string, unknown>).policy_note || "No policy note available.")}`,
      8,
    );
    const falseCandidates = Array.isArray((falsePositiveReport as Record<string, unknown>).candidates)
      ? ((falsePositiveReport as Record<string, unknown>).candidates as Array<Record<string, unknown>>)
      : [];
    writeWrapped(doc, `Candidate count: ${falseCandidates.length}`, 9);
    for (const candidate of falseCandidates.slice(0, 10)) {
      writeWrapped(
        doc,
        `- ${String(candidate.vulnerability_title || "Issue")} @ ${String(candidate.file_path || "unknown")}:${String(candidate.line_number || 1)} | reason=${String(candidate.reason_summary || "N/A")} | confidence=${String(candidate.confidence || "N/A")}`,
        8,
      );
    }
    if (falseCandidates.length > 10) {
      writeWrapped(doc, `... ${falseCandidates.length - 10} additional candidate(s) omitted in PDF.`, 8);
    }
  }

  writePdfSectionHeader(doc, "Alert Details");
  for (const group of groups.slice(0, 50)) {
    writeWrapped(doc, `[${group.severity}] ${group.title} - ${group.count} instance(s)`, 10);
    const groupCweLink = cweUrl(group.cwe);
    writeWrapped(doc, `CWE: ${group.cwe}${groupCweLink ? ` (${groupCweLink})` : ""} | OWASP: ${group.owasp}`, 8);
    const lead = group.findings[0];
    const leadExtended = lead as VulnerabilityFinding & {
      description?: string;
      tool?: string;
      cve_ids?: string[];
      known_exploited?: boolean;
      exploitability_context?: string;
    };
    writeWrapped(doc, `Tool: ${leadExtended.tool || "scanner"}`, 8);
    writeWrapped(doc, `Description: ${singleLine(leadExtended.description || "N/A")}`, 8);
    writeWrapped(doc, `CVSS: ${(lead.cvss_score || 0).toFixed(1)} (https://www.first.org/cvss/calculator/3.1)`, 8);
    const cveJoined = cveValues(leadExtended.cve_ids || []).join(", ");
    if (cveJoined) {
      writeWrapped(doc, `CVEs: ${cveJoined}`, 8);
    }
    writeWrapped(doc, `Known Exploited: ${leadExtended.known_exploited ? "Yes" : "No"}`, 8);
    if (leadExtended.exploitability_context) {
      writeWrapped(doc, `Exploitability: ${singleLine(leadExtended.exploitability_context)}`, 8);
    }
    writeWrapped(doc, `Impact: ${lead.business_impact || "N/A"}`, 8);
    writeWrapped(doc, `Recommendation: ${lead.recommendation || "N/A"}`, 8);
    const leadDependencySummary = dependencyAuthenticitySummary(lead);
    if (leadDependencySummary) {
      writeWrapped(doc, `Dependency Authenticity: ${leadDependencySummary}`, 8);
      writeWrapped(doc, `Dependency Detail: ${singleLine(dependencyAuthenticityDetail(lead))}`, 8);
    }
    writeWrapped(doc, `Attack Scenario: ${singleLine(lead.attack_scenario || "N/A")}`, 8);
    writeWrapped(doc, `Exploitation Path: ${singleLine(lead.exploitation_example || "N/A")}`, 8);
    writeWrapped(doc, "PoC Validation:", 8);
    for (const line of codeSnippetLines(lead.proof_of_concept || "N/A", 10, 180)) {
      writeWrapped(doc, `  ${line}`, 8);
    }
    writeWrapped(doc, `Active PoC Status: ${activePocStatusText(lead.active_poc)}`, 8);
    writeWrapped(doc, "Active PoC Command:", 8);
    for (const line of codeSnippetLines(activePocCommandText(lead.active_poc), 8, 180)) {
      writeWrapped(doc, `  ${line}`, 8);
    }
    writeWrapped(doc, "Active PoC Output:", 8);
    for (const line of codeSnippetLines(activePocOutputText(lead.active_poc), 10, 180)) {
      writeWrapped(doc, `  ${line}`, 8);
    }
    writeWrapped(doc, "Instances:", 8);
    for (const finding of group.findings.slice(0, 10)) {
      const findingExtended = finding as VulnerabilityFinding & { tool?: string };
      writeWrapped(
        doc,
        `  - ${normalizePath(finding.file_path)}:${finding.line_number} | ${workflowStatusText(finding.status)} | ${findingExtended.tool || "scanner"}`,
        8,
      );
    }
    doc.moveDown(0.25);
  }

  const moduleSeverity = groupFindingsByModuleSeverity(findings);
  writePdfSectionHeader(doc, "Module Severity Drill-down");
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
        `  - ${normalizePath(finding.file_path)}:${finding.line_number || 1} | ${normalizedFindingTitle(finding)}`,
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
  const fixPdfLimit = Math.max(80, Number(process.env.USS_FIX_REPORT_PDF_DETAIL_LIMIT || 180));
  const enterprise = resolveEnterpriseAssurance(scan, report.summary);
  const toolchainExecution = resolveToolchainExecution(scan, report.summary);
  const dataQualityRaw = report.summary.data_quality || scan.report.executive_summary.data_quality || null;
  const dataQuality =
    dataQualityRaw && Object.keys(dataQualityRaw).length > 0
      ? dataQualityRaw
      : deriveDataQuality(report.summary, scan.report.executive_summary, findings, toolchainExecution);
  const deterministicReplay =
    report.summary.deterministic_replay ||
    report.deterministic_replay ||
    scan.report.executive_summary.deterministic_replay ||
    null;
  const reportIntegrity =
    report.summary.report_integrity_chain ||
    report.report_integrity_chain ||
    scan.report.executive_summary.report_integrity_chain ||
    null;
  const replayRows = findings
    .filter((finding) => {
      const replay = finding.evidence_replay_pack;
      return Boolean(replay && (replay.recorded || replay.command || replay.record_sha256));
    })
    .slice(0, 40);

  writePdfHero(doc, "CodeSentinelX Original and Suggested Fix Report", [
    `Target: ${report.target_path}`,
    `Generated: ${formatDisplayTimestamp(report.generated_at)}`,
    `Total Findings: ${report.summary.total_findings}`,
  ]);
  const fixVerificationSummary = normalizedFixVerificationSummary(report.summary.fix_verification, findings);
  writePdfMetricStrip(doc, [
    { label: "Verified Fixed", value: String(fixVerificationSummary.verified_fixed), tone: "info" },
    { label: "Verification Failed", value: String(fixVerificationSummary.verification_failed), tone: "critical" },
    { label: "Inconclusive", value: String(fixVerificationSummary.inconclusive), tone: "medium" },
    { label: "Build Passed", value: String(fixVerificationSummary.build_verified), tone: "info" },
    { label: "Tests Passed", value: String(fixVerificationSummary.test_verified), tone: "info" },
  ]);
  if (Number(fixVerificationSummary.performed || 0) > 0) {
    writePdfKeyValueTable(doc, [
      { key: "Performed", value: String(fixVerificationSummary.performed) },
      { key: "Verified Fixed", value: String(fixVerificationSummary.verified_fixed) },
      { key: "Verification Failed", value: String(fixVerificationSummary.verification_failed) },
      { key: "Inconclusive", value: String(fixVerificationSummary.inconclusive) },
      { key: "Workspace Build Passed", value: String(fixVerificationSummary.build_verified) },
      { key: "Workspace Build Failed", value: String(fixVerificationSummary.build_failed) },
      { key: "Workspace Tests Passed", value: String(fixVerificationSummary.test_verified) },
      { key: "Workspace Tests Failed", value: String(fixVerificationSummary.test_failed) },
      { key: "Not Applicable", value: String(fixVerificationSummary.not_applicable) },
      { key: "Skipped", value: String(fixVerificationSummary.skipped) },
      { key: "Enterprise Status", value: String((enterprise?.status || "blocked").toUpperCase()) },
      { key: "Readiness Score", value: String(enterprise?.readiness_score ?? 0) },
      {
        key: "Required Tool Coverage",
        value: `${enterprise?.required_tools_ready ?? 0}/${enterprise?.required_tools_total ?? 0} (${(
          enterprise?.required_tools_coverage_percent ?? 0
        ).toFixed(2)}%)`,
      },
      {
        key: "Tool Success Rate",
        value: `${(toolchainExecution?.success_rate_percent ?? 0).toFixed(2)}% (${toolchainExecution?.successful_tools ?? 0}/${toolchainExecution?.attempted_tools ?? 0})`,
      },
    ]);
  }
  if (Number(fixVerificationSummary.performed || 0) === 0) {
    writeWrapped(doc, "Note: No post-fix verification was executed in this scan. Active PoC output in this report is pre-fix validation evidence only.", 8);
  }
  writePdfSectionHeader(doc, "Data Quality");
  writePdfKeyValueTable(doc, [
    { key: "Raw Findings", value: String(dataQuality.raw_findings ?? 0) },
    { key: "Deduplicated Findings", value: String(dataQuality.deduplicated_findings ?? 0) },
    { key: "Duplicates Removed", value: `${dataQuality.duplicate_findings_removed ?? 0} (${(dataQuality.dedup_ratio_percent ?? 0).toFixed(2)}%)` },
    { key: "Suppressed Findings", value: `${dataQuality.suppressed_findings ?? 0} (${(dataQuality.suppression_rate_percent ?? 0).toFixed(2)}%)` },
    { key: "Tool Success Rate", value: `${(dataQuality.tool_success_rate_percent ?? 0).toFixed(2)}%` },
    { key: "Coverage Confidence", value: `${String(dataQuality.coverage_confidence || "N/A")} (${(dataQuality.coverage_confidence_score ?? 0).toFixed(1)})` },
    { key: "Unknown Rule IDs", value: String(dataQuality.unknown_rule_count ?? 0) },
    { key: "Unknown CWE", value: String(dataQuality.unknown_cwe_count ?? 0) },
    { key: "Unknown OWASP", value: String(dataQuality.unknown_owasp_count ?? 0) },
    { key: "Taxonomy Gaps", value: String(dataQuality.unknown_taxonomy_count ?? 0) },
  ]);
  writePdfSectionHeader(doc, "Deterministic Evidence Replay Pack");
  if (!hasReplaySummaryData(deterministicReplay)) {
    writeWrapped(doc, "No deterministic replay evidence metadata was captured for this scan.", 9);
  } else {
    const replayData = deterministicReplay as NonNullable<typeof deterministicReplay>;
    writePdfKeyValueTable(doc, [
      { key: "Mode", value: String(replayData.mode || "deterministic-evidence-replay") },
      { key: "Replay Coverage", value: `${Number(replayData.replay_coverage_percent || 0).toFixed(2)}%` },
      {
        key: "Findings with Replay",
        value: `${Number(replayData.findings_with_replay || 0)}/${Number(replayData.findings_total || 0)}`,
      },
      { key: "Evidence Records", value: String(Number(replayData.tool_evidence_records || 0)) },
      {
        key: "Tools with Evidence",
        value:
          Array.isArray(replayData.tools_with_evidence) && replayData.tools_with_evidence.length
            ? replayData.tools_with_evidence.join(", ")
            : "N/A",
      },
    ]);
    for (const finding of replayRows) {
      const replay = finding.evidence_replay_pack || {};
      writeWrapped(
        doc,
        `- ${finding.finding_uid} | ${normalizedFindingTitle(finding)} | tool=${replay.tool || "N/A"} | recorded=${replay.recorded ? "yes" : "no"}`,
        8,
      );
      writeWrapped(
        doc,
        `  command=${String(replay.command || "N/A")} | record_sha256=${String(replay.record_sha256 || "N/A")}`,
        8,
      );
    }
  }
  writePdfSectionHeader(doc, "Tamper-Evident Report Chain");
  if (!hasIntegrityChainData(reportIntegrity)) {
    writeWrapped(doc, "No report integrity chain metadata was captured for this scan.", 9);
  } else {
    const integrityData = reportIntegrity as NonNullable<typeof reportIntegrity>;
    writePdfKeyValueTable(doc, [
      { key: "Chain Version", value: String(integrityData.chain_version || "1.0") },
      { key: "Tamper Evident", value: integrityData.tamper_evident ? "Yes" : "No" },
      { key: "Generated At", value: String(integrityData.generated_at || "N/A") },
      { key: "Report SHA256", value: String(integrityData.report_sha256 || "N/A") },
      { key: "Findings SHA256", value: String(integrityData.findings_sha256 || "N/A") },
      { key: "Tool Evidence SHA256", value: String(integrityData.tool_evidence_sha256 || "N/A") },
      { key: "Metadata SHA256", value: String(integrityData.metadata_sha256 || "N/A") },
      { key: "Previous Report SHA256", value: String(integrityData.previous_report_sha256 || "N/A") },
      { key: "Chain Note", value: String(integrityData.chain_note || "N/A") },
    ]);
  }
  for (const blocker of (enterprise?.blockers || []).slice(0, 6)) {
    writeWrapped(doc, `- ${blocker}`, 8);
  }
  writePdfSectionHeader(doc, "Fix Guidance Queue");

  for (const finding of findings.slice(0, fixPdfLimit)) {
    writeWrapped(
      doc,
      `[${finding.severity}] ${normalizedFindingTitle(finding)} | CVSS ${(finding.cvss_score || 0).toFixed(1)}`,
      10,
    );
    const cweLink = cweUrl(finding.cwe_id || "");
    writeWrapped(
      doc,
      `Location: ${normalizePath(finding.file_path)}:${finding.line_number || 1} | ${finding.cwe_id || "N/A"}${cweLink ? ` (${cweLink})` : ""} | ${finding.owasp_mapping || "N/A"}`,
      8,
    );
    writeWrapped(doc, "CVSS Reference: https://www.first.org/cvss/calculator/3.1", 8);
    const cves = cveValues(finding.cve_ids || []);
    const advisoryIds = advisoryValues(finding);
    if (advisoryIds.length) {
      writeWrapped(doc, `CVE / Advisory IDs: ${advisoryIds.join(", ")}`, 8);
    }
    writeWrapped(doc, `Recommendation: ${finding.recommendation || "N/A"}`, 8);
    const dependencySummary = dependencyAuthenticitySummary(finding);
    if (dependencySummary) {
      writeWrapped(doc, `Dependency Authenticity: ${dependencySummary}`, 8);
      writeWrapped(doc, `Dependency Detail: ${singleLine(dependencyAuthenticityDetail(finding))}`, 8);
    }
    if (finding.attack_scenario) {
      writeWrapped(doc, `Attack Scenario: ${singleLine(finding.attack_scenario)}`, 8);
    }
    if (finding.exploitation_example) {
      writeWrapped(doc, `Exploitation Path: ${singleLine(finding.exploitation_example)}`, 8);
    }
    if (finding.proof_of_concept) {
      writeWrapped(doc, "PoC Validation:", 8);
      for (const line of codeSnippetLines(finding.proof_of_concept, 14, 180)) {
        writeWrapped(doc, `  ${line}`, 8);
      }
    }
    writeWrapped(doc, `Active PoC Status: ${activePocStatusText(finding.active_poc)}`, 8);
    writeWrapped(doc, "Active PoC Command:", 8);
    for (const line of codeSnippetLines(activePocCommandText(finding.active_poc), 10, 180)) {
      writeWrapped(doc, `  ${line}`, 8);
    }
    writeWrapped(doc, "Active PoC Output:", 8);
    const activeStatus = String(finding.active_poc?.status || "").toLowerCase();
    const activeOutput =
      activeStatus && activeStatus !== "skipped"
        ? activePocOutputText(finding.active_poc)
        : "Active PoC output omitted for skipped/not-executed checks to keep PDF compact.";
    for (const line of codeSnippetLines(activeOutput, 12, 180)) {
      writeWrapped(doc, `  ${line}`, 8);
    }
    writeWrapped(
      doc,
      `Fix Verification Result: ${fixVerificationResultText(finding.fix_verification)} | Reason: ${fixVerificationReasonText(finding.fix_verification)}`,
      8,
    );
    writeWrapped(doc, "Post-Fix Verification Command:", 8);
    for (const line of codeSnippetLines(String(finding.fix_verification?.post_fix_execution?.command || "No post-fix verification command was executed for this finding in this scan."), 10, 180)) {
      writeWrapped(doc, `  ${line}`, 8);
    }
    writeWrapped(doc, "Post-Fix Verification Output:", 8);
    for (const line of codeSnippetLines(String(finding.fix_verification?.post_fix_execution?.output || "No post-fix verification output was captured for this finding in this scan."), 12, 180)) {
      writeWrapped(doc, `  ${line}`, 8);
    }
    if (finding.fix_verification?.build_verification) {
      writeWrapped(doc, "Workspace Build Verification:", 8);
      for (const line of codeSnippetLines(String(finding.fix_verification.build_verification.command || "N/A"), 10, 180)) {
        writeWrapped(doc, `  ${line}`, 8);
      }
      for (const line of codeSnippetLines(String(finding.fix_verification.build_verification.output || "No build output captured."), 12, 180)) {
        writeWrapped(doc, `  ${line}`, 8);
      }
    }
    if (finding.fix_verification?.test_verification) {
      writeWrapped(doc, "Workspace Test Verification:", 8);
      for (const line of codeSnippetLines(String(finding.fix_verification.test_verification.command || "N/A"), 10, 180)) {
        writeWrapped(doc, `  ${line}`, 8);
      }
      for (const line of codeSnippetLines(String(finding.fix_verification.test_verification.output || "No test output captured."), 12, 180)) {
        writeWrapped(doc, `  ${line}`, 8);
      }
    }
    writeWrapped(doc, "Original Code:", 8);
    for (const line of codeSnippetLines(finding.original_code || "Snippet unavailable.", 12, 180)) {
      writeWrapped(doc, `  ${line}`, 8);
    }
    writeWrapped(doc, `AI Remediation Summary: ${singleLine(resolvedAiRemediationSummary(finding))}`, 8);
    writeWrapped(
      doc,
      `AI Fix Confidence: ${aiFixConfidenceLabel(finding)} (${aiFixConfidenceScore(finding).toFixed(2)}) | Grounded: ${aiGroundingStatus(finding)} | Source: ${String(finding.ai_fix_source || "local-evidence-driven:evidence-rules-v1")}`,
      8,
    );
    writeWrapped(doc, `Grounding Notes: ${singleLine(aiGroundingNotes(finding))}`, 8);
    writeWrapped(doc, "AI Validation Steps:", 8);
    for (const line of codeSnippetLines(resolvedAiValidationSteps(finding), 10, 180)) {
      writeWrapped(doc, `  ${line}`, 8);
    }
    if (finding.ai_validation_steps) {
      writeWrapped(doc, `AI Validation Steps: ${singleLine(finding.ai_validation_steps)}`, 8);
    }
    writeWrapped(doc, `${fixArtifactLabel(finding)}:`, 8);
    for (const line of codeSnippetLines(preferredFindingFix(finding), 12, 180)) {
      writeWrapped(doc, `  ${line}`, 8);
    }
    if (fixArtifactKind(finding) === "exact_patch" && finding.patch_preview) {
      writeWrapped(doc, "Patch Preview:", 8);
      for (const line of codeSnippetLines(finding.patch_preview, 12, 180)) {
        writeWrapped(doc, `  ${line}`, 8);
      }
    } else if (fixArtifactKind(finding) !== "exact_patch") {
      writeWrapped(doc, "Patch Preview: Guidance-only remediation does not include an exact patch.", 8);
    }
    doc.moveDown(0.35);
  }

  if (findings.length > fixPdfLimit) {
    writeWrapped(doc, `Truncated after ${fixPdfLimit} entries. Additional findings: ${findings.length - fixPdfLimit}`, 9);
  }
}

function writeCombinedPdf(doc: PDFKit.PDFDocument, scan: ScanView): void {
  doc.fontSize(18).text("CodeSentinelX Combined Security Report");
  doc.moveDown(0.3).fontSize(10).text(`Target: ${scan.report.executive_summary.target_path}`);
  doc.text(`Risk Score: ${scan.report.executive_summary.risk_score} (${scan.report.executive_summary.risk_rating})`);
  doc.moveDown(0.7).fontSize(11).text("Use separate Existing and Vulnerability reports for full evidence.");
}

function writeFindingDetailsPdf(doc: PDFKit.PDFDocument, scan: ScanView): void {
  const findings = sortedFindings(scan.report.vulnerability_fixed_code_report.findings || []);
  const report = scan.report.vulnerability_fixed_code_report;
  writePdfHero(doc, "CodeSentinelX Finding Details Report", [
    `Target: ${report.target_path}`,
    `Generated: ${formatDisplayTimestamp(report.generated_at)}`,
    `Total Findings: ${findings.length}`,
  ]);
  writePdfSectionHeader(doc, "Finding Details");

  for (const finding of findings.slice(0, 320)) {
    writeWrapped(doc, `[${finding.severity}] ${normalizedFindingTitle(finding)}`, 9);
    writeWrapped(doc, `Location: ${normalizePath(finding.file_path)}:${finding.line_number || 1}`, 8);
    writeWrapped(doc, `Issue Description: ${finding.description || finding.business_impact || "N/A"}`, 8);
    writeWrapped(doc, `Remediation: ${preferredFindingFix(finding)}`, 8);
    writeWrapped(doc, "", 8);
  }

  if (findings.length > 320) {
    writeWrapped(doc, `Truncated after 320 entries. Additional findings: ${findings.length - 320}`, 8);
  }
}

function drawPdfReportBackdrop(doc: PDFKit.PDFDocument): void {
  const pageWidth = doc.page.width;
  const pageHeight = doc.page.height;
  const globeSize = Math.min(pageWidth * 1.08, 505);
  const globeX = pageWidth - globeSize * 0.34;
  const globeY = -8;

  doc.save();
  doc.fillColor("#06111d").rect(0, 0, pageWidth, pageHeight).fill();
  doc.opacity(0.14).fillColor("#0a1c31").rect(0, 0, pageWidth, pageHeight * 0.32).fill();
  doc.opacity(0.08).fillColor("#12304c").rect(0, pageHeight * 0.68, pageWidth, pageHeight * 0.32).fill();
  doc.restore();

  doc.save();
  doc.circle(globeX, globeY + globeSize / 2, globeSize / 2).clip();
  doc.opacity(0.34);
  if (REPORT_GLOBE_TEXTURE_PATH) {
    doc.image(REPORT_GLOBE_TEXTURE_PATH, globeX - globeSize / 2, globeY, {
      width: globeSize,
      height: globeSize,
    });
  } else {
    doc.fillColor("#11253d").circle(globeX, globeY + globeSize / 2, globeSize / 2).fill();
  }
  doc.restore();

  doc.save();
  doc.opacity(0.32);
  doc.lineWidth(1);
  doc.strokeColor("#2f567a").circle(globeX, globeY + globeSize / 2, globeSize / 2).stroke();
  doc.opacity(0.2);
  doc.strokeColor("#5dc9ff").circle(globeX, globeY + globeSize / 2, globeSize / 2 + 10).stroke();
  doc.restore();

  doc.save();
  doc.opacity(0.14);
  doc.strokeColor("#5dc9ff").lineWidth(0.8);
  doc.moveTo(globeX - globeSize * 0.42, globeY + globeSize * 0.48)
    .lineTo(globeX + globeSize * 0.42, globeY + globeSize * 0.48)
    .stroke();
  doc.restore();

  doc.fillColor("#dce9f7");
}

function writeWrapped(doc: PDFKit.PDFDocument, text: string, fontSize: number): void {
  if (doc.y > doc.page.height - 52) {
    doc.addPage();
  }
  doc.fontSize(fontSize).text(text, { width: doc.page.width - 64, lineGap: 1.5 });
}

function ensurePdfSpace(doc: PDFKit.PDFDocument, height: number): void {
  if (doc.y + height > doc.page.height - 42) {
    doc.addPage();
  }
}

function writePdfHero(doc: PDFKit.PDFDocument, title: string, meta: string[]): void {
  const x = doc.page.margins.left;
  const y = doc.y;
  const width = doc.page.width - doc.page.margins.left - doc.page.margins.right;
  const height = 62 + meta.length * 15;
  ensurePdfSpace(doc, height + 8);
  doc.save();
  doc.fillOpacity(0.72);
  doc.roundedRect(x, y, width, height, 12).fillAndStroke("#0b1b2d", "#27496c");
  doc.fillOpacity(1);
  doc.fillColor("#f5fbff").font("Helvetica-Bold").fontSize(19).text(title, x + 16, y + 12, { width: width - 32 });
  doc.font("Helvetica").fontSize(9.5).fillColor("#9eb6ce");
  meta.forEach((line, index) => {
    doc.text(line, x + 16, y + 38 + index * 13, { width: width - 32 });
  });
  doc.restore();
  doc.fillColor("#dce9f7");
  doc.y = y + height + 10;
}

function writePdfSectionHeader(doc: PDFKit.PDFDocument, title: string): void {
  ensurePdfSpace(doc, 26);
  const x = doc.page.margins.left;
  const width = doc.page.width - doc.page.margins.left - doc.page.margins.right;
  doc.font("Helvetica-Bold").fontSize(13).fillColor("#f5fbff").text(title, x, doc.y);
  const lineY = doc.y + 4;
  doc.moveTo(x, lineY).lineTo(x + width, lineY).strokeColor("#2d5376").lineWidth(0.7).stroke();
  doc.moveDown(0.55);
  doc.fillColor("#dce9f7").font("Helvetica");
}

function writePdfKeyValueTable(
  doc: PDFKit.PDFDocument,
  rows: Array<{ key: string; value: string }>,
  options?: { keyWidthRatio?: number; rowHeight?: number },
): void {
  if (!rows.length) {
    return;
  }
  const keyWidthRatio = Math.max(0.2, Math.min(0.7, Number(options?.keyWidthRatio || 0.48)));
  const rowHeight = Math.max(18, Number(options?.rowHeight || 20));
  const x = doc.page.margins.left;
  const width = doc.page.width - doc.page.margins.left - doc.page.margins.right;
  const keyWidth = Math.floor(width * keyWidthRatio);
  const valueWidth = width - keyWidth;
  const totalRows = rows.length + 1;
  const totalHeight = totalRows * rowHeight + 8;
  ensurePdfSpace(doc, totalHeight);

  let cursorY = doc.y;
  const startY = cursorY;
  doc.save();
  doc.fillOpacity(0.74);
  doc.roundedRect(x, cursorY, width, totalRows * rowHeight, 8).fillAndStroke("#0b1b2d", "#27496c");
  doc.fillOpacity(1);
  doc
    .fillColor("#c8dbef")
    .font("Helvetica-Bold")
    .fontSize(8.5)
    .text("Metric", x + 10, cursorY + 6, { width: keyWidth - 16, ellipsis: true })
    .text("Value", x + keyWidth + 10, cursorY + 6, { width: valueWidth - 16, ellipsis: true });
  cursorY += rowHeight;
  doc.moveTo(x + keyWidth, startY).lineTo(x + keyWidth, startY + totalRows * rowHeight).strokeColor("#264867").lineWidth(0.8).stroke();
  for (let i = 0; i < rows.length; i += 1) {
    const row = rows[i];
    const shade = i % 2 === 0 ? "#0d2238" : "#102840";
    doc.rect(x, cursorY, width, rowHeight).fillAndStroke(shade, "#1f3c5a");
    doc
      .fillColor("#9eb6ce")
      .font("Helvetica")
      .fontSize(8.5)
      .text(row.key, x + 10, cursorY + 6, { width: keyWidth - 16, ellipsis: true })
      .fillColor("#f5fbff")
      .text(row.value, x + keyWidth + 10, cursorY + 6, { width: valueWidth - 16, ellipsis: true });
    cursorY += rowHeight;
  }
  doc.restore();
  doc.y = cursorY + 8;
  doc.fillColor("#dce9f7").font("Helvetica");
}

function writePdfMetricStrip(
  doc: PDFKit.PDFDocument,
  metrics: Array<{ label: string; value: string; tone?: "critical" | "high" | "medium" | "low" | "info" | "accent" }>,
): void {
  if (!metrics.length) {
    return;
  }
  const colors: Record<string, string> = {
    critical: "#3b1020",
    high: "#3b2411",
    medium: "#3b3112",
    low: "#112f47",
    info: "#123327",
    accent: "#103149",
  };
  const x = doc.page.margins.left;
  const width = doc.page.width - doc.page.margins.left - doc.page.margins.right;
  const gap = 8;
  const columns = Math.max(1, Math.min(3, metrics.length));
  const cardWidth = (width - gap * (columns - 1)) / columns;
  const rowHeight = 48;
  const rows = Math.ceil(metrics.length / columns);
  ensurePdfSpace(doc, rows * (rowHeight + gap));
  const startY = doc.y;
  metrics.forEach((metric, index) => {
    const row = Math.floor(index / columns);
    const col = index % columns;
    const cardX = x + col * (cardWidth + gap);
    const cardY = startY + row * (rowHeight + gap);
    doc.save();
    doc.fillOpacity(0.82);
    doc.roundedRect(cardX, cardY, cardWidth, rowHeight, 8).fillAndStroke(colors[metric.tone || "accent"] || colors.accent, "#254a69");
    doc.fillOpacity(1);
    doc.fillColor("#95b7d6").font("Helvetica").fontSize(7.5).text(metric.label.toUpperCase(), cardX + 10, cardY + 9, {
      width: cardWidth - 16,
    });
    doc.fillColor("#f5fbff").font("Helvetica-Bold").fontSize(15).text(metric.value, cardX + 10, cardY + 23, {
      width: cardWidth - 16,
    });
    doc.restore();
  });
  doc.y = startY + rows * rowHeight + (rows - 1) * gap + 8;
  doc.fillColor("#dce9f7").font("Helvetica");
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
  const controlEvidenceRows = report.controls
    .flatMap((control) => {
      const evidence = Array.isArray((control as { evidence?: Array<Record<string, unknown>> }).evidence)
        ? ((control as { evidence?: Array<Record<string, unknown>> }).evidence || [])
        : [];
      return evidence.slice(0, 8).map((row) => {
        const rec = row as Record<string, unknown>;
        const file = normalizePath(String(rec.file_path || "N/A"));
        const line = Number(rec.line_number || 1);
        const snippet = String(rec.snippet || "").trim();
        return `<tr>
      <td>${escapeHtml(control.name)}</td>
      <td>${escapeHtml(file)}</td>
      <td align="center">${line}</td>
      <td><code>${escapeHtml(snippet || "N/A")}</code></td>
    </tr>`;
      });
    })
    .join("");

  const profileHeader = profileCompliance
    ? `<p class="meta"><strong>Profile:</strong> ${escapeHtml(profileCompliance.scan_profile_label)} (${escapeHtml(profileCompliance.scan_profile)})</p>
  <p class="meta"><strong>Framework Versions:</strong> OWASP Top 10 ${escapeHtml(profileCompliance.framework_versions.owasp_top_10)} | API Top 10 ${escapeHtml(profileCompliance.framework_versions.owasp_api_top_10)} | ASVS ${escapeHtml(profileCompliance.framework_versions.asvs)} | WSTG ${escapeHtml(profileCompliance.framework_versions.wstg)}</p>
  <p class="meta"><strong>Reference:</strong> OWASP Top 10 latest official published release is 2021.</p>`
    : "";

  const profileFrameworks = profileCompliance
    ? profileCompliance.frameworks
        .map((framework) => {
          const rows = framework.rows
            .map((row, index) => {
              const rowAny = row as unknown as Record<string, unknown>;
              const rowId = String(rowAny.id ?? rowAny.item_id ?? rowAny.key ?? `ITEM-${index + 1}`);
              const rowTitle = String(rowAny.title ?? rowAny.category ?? rowAny.name ?? rowAny.label ?? "Unlabeled");
              const statusRaw = String(rowAny.status ?? rowAny.coverage_status ?? "gap").replaceAll("_", " ");
              const findings = Number(rowAny.finding_count ?? rowAny.findings ?? 0);
              const controls = Number(rowAny.control_count ?? rowAny.controls ?? 0);
              const total = Number(rowAny.count ?? (findings + controls));
              return `<tr>
      <td>${escapeHtml(rowId && rowId !== "undefined" ? rowId : `ITEM-${index + 1}`)}</td>
      <td>${escapeHtml(rowTitle && rowTitle !== "undefined" ? rowTitle : "Unlabeled")}</td>
      <td>${escapeHtml(statusRaw && statusRaw !== "undefined" ? statusRaw : "gap")}</td>
      <td>${Number.isFinite(findings) ? findings : 0}</td>
      <td>${Number.isFinite(controls) ? controls : 0}</td>
      <td>${Number.isFinite(total) ? total : 0}</td>
    </tr>`;
            })
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

  const summary = report.summary;
  const coverageCategoryBars = renderMetricBars(
    "Category Distribution",
    Object.entries(summary.category_distribution || {}).map(([label, value]) => ({
      label,
      value: Number(value || 0),
      tone: "low",
    })),
  );
  const coverageLevelBars = renderMetricBars(
    "Coverage Levels",
    Object.entries(summary.coverage_levels || {}).map(([label, value]) => ({
      label,
      value: Number(value || 0),
      tone: "info",
    })),
  );
  const existingCards = renderStatGrid([
    {
      label: "Implemented Controls",
      value: Number(summary.implemented_controls || 0),
      tone: "accent",
      sub: "Controls with direct evidence in the scanned repository",
    },
    {
      label: "Security Domains",
      value: Object.keys(summary.category_distribution || {}).length,
      tone: "low",
      sub: "Distinct control categories observed",
    },
    {
      label: "Coverage Levels",
      value: Object.keys(summary.coverage_levels || {}).length,
      tone: "info",
      sub: "Unique coverage classifications present",
    },
    {
      label: "Standards Mapped",
      value: Object.keys(summary.standards_coverage || {}).length,
      tone: "medium",
      sub: "Framework families referenced by the detected controls",
    },
  ]);

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>CodeSentinelX Existing Security Report</title>
  <style>${exportThemeCss()}</style>
</head>
<body>
  <main class="report-shell">
    <section class="hero">
      <h1>CodeSentinelX Existing Security Implementation Report</h1>
      <div class="hero-meta">
        <div class="meta-pill"><strong>Target:</strong> ${escapeHtml(report.target_path)}</div>
        <div class="meta-pill"><strong>Generated:</strong> ${escapeHtml(formatDisplayTimestamp(report.generated_at))}</div>
        <div class="meta-pill"><strong>Profile:</strong> ${escapeHtml(profileCompliance?.scan_profile_label || "Codebase")}</div>
      </div>
      ${existingCards}
      <div class="callout" style="margin-top:14px">
        <strong>Purpose:</strong> This report highlights controls already implemented in the repository. It excludes vulnerability findings and focuses on what is present, mapped, and reusable during reviews.
      </div>
      <div class="meta" style="margin-top:10px">${profileHeader}</div>
    </section>

    <section class="section">
      <div class="section-grid">
        <div class="stack">
          <div class="table-frame">
            <h2 style="padding:12px 14px 0">Coverage Summary</h2>
            <div class="table-scroll">
              <table>
                <thead><tr><th>Metric</th><th>Value</th></tr></thead>
                <tbody>${summaryRows.join("") || "<tr><td colspan='2'>No summary data available.</td></tr>"}</tbody>
              </table>
            </div>
            <div style="padding:10px 14px 14px">
              ${coverageCategoryBars}
              <hr class="section-divider" />
              ${coverageLevelBars}
            </div>
          </div>
          <div class="table-frame">
            <h2 style="padding:12px 14px 0">Implemented Controls</h2>
            <div class="table-scroll">
              <table>
                <thead><tr><th>Control</th><th>Category</th><th>Coverage</th><th>Standards</th></tr></thead>
                <tbody>${controlRows.join("") || "<tr><td colspan='4'>No controls detected.</td></tr>"}</tbody>
              </table>
            </div>
          </div>
          <div class="table-frame">
            <h2 style="padding:12px 14px 0">Control Evidence (File/Line)</h2>
            <div class="table-scroll">
              <table>
                <thead><tr><th>Control</th><th>File</th><th>Line</th><th>Evidence Snippet</th></tr></thead>
                <tbody>${controlEvidenceRows || "<tr><td colspan='4'>No control-level evidence captured.</td></tr>"}</tbody>
              </table>
            </div>
          </div>
        </div>
        <div class="stack">
          <div class="table-frame">
            <h2 style="padding:12px 14px 0">Profile-Based Coverage</h2>
            <div style="padding:0 14px 14px">${profileFrameworks}</div>
          </div>
          <div class="table-frame">
            <h2 style="padding:12px 14px 0">Compliance Matrix</h2>
            <div class="table-scroll">
              <table>
                <thead><tr><th>Standard</th><th>Control Count</th><th>Status</th></tr></thead>
                <tbody>${renderComplianceMatrixRows(report.compliance_matrix || []) || "<tr><td colspan='3'>No compliance mapping data.</td></tr>"}</tbody>
              </table>
            </div>
          </div>
        </div>
      </div>
      <p class="table-note">Design goal: leadership can see coverage posture quickly, while engineers can still drill into control names, mapped standards, and framework gaps in the same export.</p>
    </section>
  </main>
</body>
</html>`;
}

function renderVulnerabilityHtml(scan: ScanView): string {
  const report = scan.report.vulnerability_fixed_code_report;
  const findings = sortedFindings(report.findings || []);
  const EXEC_LIMIT = 60;
  const DETAIL_LIMIT = 120;
  const groupedAll = groupByAlert(findings);
  const grouped = groupedAll.slice(0, EXEC_LIMIT);
  const fileAggAll = aggregateFiles(findings);
  const fileAgg = fileAggAll.slice(0, EXEC_LIMIT);
  const moduleAggAll = report.summary.affected_modules || [];
  const moduleAgg = moduleAggAll.slice(0, EXEC_LIMIT);
  const owaspAggAll = report.summary.top_owasp_categories || [];
  const owaspAgg = owaspAggAll.slice(0, EXEC_LIMIT);
  const actionPlan = scan.report.executive_summary.recommended_action_plan || [];
  const summaryExtras = report.summary as VulnerabilityFixedCodeReport["summary"] & {
    release_gate_distribution?: Record<string, number>;
    risk_intelligence?: { findings_with_cve?: number; findings_cvss_ge_7?: number; known_exploited_findings?: number };
    git_diff_tracking?: { enabled?: boolean; changed_files?: number; findings_on_changed_files?: number; findings_on_changed_lines?: number };
    auth_abuse_session_security?: {
      total_findings?: number;
      severity_distribution?: Record<string, number>;
      top_vulnerability_types?: Array<{ type: string; count: number }>;
      affected_modules?: Array<{ module: string; count: number; critical: number; high: number }>;
      affected_files?: Array<{ file: string; folder: string; count: number; critical: number; high: number }>;
    };
    deterministic_replay?: {
      enabled?: boolean;
      mode?: string;
      findings_total?: number;
      findings_with_replay?: number;
      findings_without_replay?: number;
      replay_coverage_percent?: number;
      tool_evidence_records?: number;
      tools_with_evidence?: string[];
      tool_mismatch_counts?: Record<string, number>;
      record_hashes?: string[];
    };
    report_integrity_chain?: {
      chain_version?: string;
      tamper_evident?: boolean;
      generated_at?: string;
      metadata_sha256?: string;
      findings_sha256?: string;
      tool_evidence_sha256?: string;
      report_sha256?: string;
      previous_report_sha256?: string | null;
    };
    data_quality?: DataQualitySummary;
    enterprise_assurance?: EnterpriseAssuranceSummary;
    toolchain_execution?: ToolchainExecutionSummary;
  };
  const releaseGateDistribution: Record<string, number> = summaryExtras.release_gate_distribution || {};
  const riskIntel = resolveRiskIntelligence(summaryExtras, findings);
  const gitDiffTracking = summaryExtras.git_diff_tracking
    ? {
        enabled: Boolean(summaryExtras.git_diff_tracking.enabled),
        changed_files: Number(summaryExtras.git_diff_tracking.changed_files || 0),
        findings_on_changed_files: Number(summaryExtras.git_diff_tracking.findings_on_changed_files || 0),
        findings_on_changed_lines: Number(summaryExtras.git_diff_tracking.findings_on_changed_lines || 0),
      }
    : null;
  const authAbuse = resolveAuthAbuse(summaryExtras, findings);
  const deterministicReplay =
    summaryExtras.deterministic_replay ||
    (report as VulnerabilityFixedCodeReport & { deterministic_replay?: NonNullable<typeof summaryExtras.deterministic_replay> }).deterministic_replay ||
    scan.report.executive_summary.deterministic_replay ||
    null;
  const reportIntegrity =
    summaryExtras.report_integrity_chain ||
    (report as VulnerabilityFixedCodeReport & { report_integrity_chain?: NonNullable<typeof summaryExtras.report_integrity_chain> }).report_integrity_chain ||
    scan.report.executive_summary.report_integrity_chain ||
    null;
  const toolchainExecution = resolveToolchainExecution(scan, report.summary);
  const dataQualityRaw = summaryExtras.data_quality || scan.report.executive_summary.data_quality || null;
  const dataQuality =
    dataQualityRaw && Object.keys(dataQualityRaw).length > 0
      ? dataQualityRaw
      : deriveDataQuality(report.summary, scan.report.executive_summary, findings, toolchainExecution);
  const enterprise = resolveEnterpriseAssurance(scan, report.summary);
  const dataQualityRows = dataQuality
    ? `
      <tr><td>Raw Findings</td><td>${Number(dataQuality.raw_findings || 0)}</td></tr>
      <tr><td>Deduplicated Findings</td><td>${Number(dataQuality.deduplicated_findings || 0)}</td></tr>
      <tr><td>Duplicates Removed</td><td>${Number(dataQuality.duplicate_findings_removed || 0)} (${Number(dataQuality.dedup_ratio_percent || 0).toFixed(2)}%)</td></tr>
      <tr><td>Suppressed Findings</td><td>${Number(dataQuality.suppressed_findings || 0)} (${Number(dataQuality.suppression_rate_percent || 0).toFixed(2)}%)</td></tr>
      <tr><td>Tool Success Rate</td><td>${Number(dataQuality.tool_success_rate_percent || 0).toFixed(2)}%</td></tr>
      <tr><td>Coverage Confidence</td><td>${escapeHtml(String(dataQuality.coverage_confidence || "N/A"))} (${Number(dataQuality.coverage_confidence_score || 0).toFixed(1)})</td></tr>
      <tr><td>Unknown Rule IDs</td><td>${Number(dataQuality.unknown_rule_count || 0)}</td></tr>
      <tr><td>Unknown CWE</td><td>${Number(dataQuality.unknown_cwe_count || 0)}</td></tr>
      <tr><td>Unknown OWASP</td><td>${Number(dataQuality.unknown_owasp_count || 0)}</td></tr>
      <tr><td>Findings with Taxonomy Gaps</td><td>${Number(dataQuality.unknown_taxonomy_count || 0)}</td></tr>
    `
    : `<tr><td colspan="2" class="muted">No data quality metrics available.</td></tr>`;
  const executionEvidence = collectExecutionEvidenceRows(report.toolchain_status || {}).slice(0, EXEC_LIMIT);
  const roleAware = report.role_aware_report || scan.report.role_aware_report || {};
  const roleAwareRecord = roleAware as unknown as Record<string, unknown>;
  const ctoBoard = resolveCtoBoardView(roleAwareRecord, findings, report.summary, riskIntel);
  const cisoView = resolveCisoSecurityView(roleAwareRecord, findings);
  const devView = resolveDeveloperDevopsView(roleAwareRecord, findings);
  const riskStory = resolveRiskStoryMode(roleAwareRecord, findings);
  const advanced = resolveAdvancedFeatures(roleAwareRecord, findings, enterprise, dataQuality);
  const falsePositiveReport =
    report.false_positive_report ||
    scan.report.false_positive_report ||
    (roleAware.false_positive_report as Record<string, unknown>) ||
    {};
  const moduleSeverityCatalog = groupFindingsByModuleSeverity(findings);
  const drillData = findings.map((finding) => ({
    finding_uid: finding.finding_uid,
    severity: finding.severity,
    issue: normalizedFindingTitle(finding),
    file: normalizePath(finding.file_path),
    folder: folderFromPath(finding.file_path),
    module: moduleFromFinding(finding),
    line: finding.line_number || 1,
    cwe: finding.cwe_id || "N/A",
    cwe_url: cweUrl(finding.cwe_id || ""),
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
    <td>${renderCweLink(group.cwe)}</td>
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
  const enterpriseBlockers = (enterprise?.blockers || [])
    .slice(0, 12)
    .map((item) => `<li>${escapeHtml(item)}</li>`)
    .join("");

  const details = grouped
    .map((group) => {
      const lead = group.findings[0];
      const leadExtended = lead as VulnerabilityFinding & {
        description?: string;
        tool?: string;
        release_gate_action?: string;
        exploit_maturity?: string;
        cve_ids?: string[];
        known_exploited?: boolean;
        exploitability_context?: string;
      };
      const cveList =
        Array.isArray(leadExtended.cve_ids) && leadExtended.cve_ids.length
          ? leadExtended.cve_ids
          : "N/A";
      const instanceRows = group.findings
        .slice(0, DETAIL_LIMIT)
        .map(
          (finding) => `<tr>
      <td>${escapeHtml(normalizePath(finding.file_path))}</td>
      <td>${escapeHtml(folderFromPath(finding.file_path))}</td>
      <td align="center">${finding.line_number || 1}</td>
      <td>${escapeHtml(workflowStatusText(finding.status))}</td>
      <td>${escapeHtml(String((finding as VulnerabilityFinding & { tool?: string }).tool || "scanner"))}</td>
      <td>${renderCweLink(finding.cwe_id || "N/A")}</td>
      <td>${escapeHtml(finding.owasp_mapping || "N/A")}</td>
    </tr>`,
        )
        .join("");

      return `<section id="${escapeHtml(group.id)}" class="alert-section hidden-section">
    <h3>[${escapeHtml(group.severity)}] ${escapeHtml(group.title)} (${group.count})</h3>
    <table class="results">
      <tr><th width="20%">CWE</th><td>${renderCweLink(group.cwe)}</td></tr>
      <tr><th>OWASP</th><td>${escapeHtml(group.owasp)}</td></tr>
      <tr><th>CVSS</th><td>${renderCvssLink(lead.cvss_score)}</td></tr>
      <tr><th>Description</th><td>${escapeHtml(leadExtended.description || "N/A")}</td></tr>
      <tr><th>Business Impact</th><td>${escapeHtml(lead.business_impact || "N/A")}</td></tr>
      <tr><th>Release Gate</th><td>${escapeHtml(leadExtended.release_gate_action || "Track")}</td></tr>
      <tr><th>Exploit Maturity</th><td>${escapeHtml(leadExtended.exploit_maturity || "Unconfirmed")}</td></tr>
      <tr><th>Known Exploited (CISA KEV)</th><td>${leadExtended.known_exploited ? "Yes" : "No"}</td></tr>
      <tr><th>CVEs</th><td>${renderCveLinks(cveList)}</td></tr>
      <tr><th>Exploitability Context</th><td>${escapeHtml(leadExtended.exploitability_context || "N/A")}</td></tr>
      <tr><th>Recommendation</th><td>${escapeHtml(lead.recommendation || "N/A")}</td></tr>
      ${dependencyAuthenticitySummary(lead) ? `<tr><th>Dependency Authenticity</th><td>${escapeHtml(dependencyAuthenticitySummary(lead))}<br><span class="muted">${escapeHtml(dependencyAuthenticityDetail(lead))}</span></td></tr>` : ""}
      <tr><th>Attack Scenario</th><td>${escapeHtml(lead.attack_scenario || "N/A")}</td></tr>
      <tr><th>Exploitation Path</th><td>${escapeHtml(lead.exploitation_example || "N/A")}</td></tr>
      <tr><th>Source Tool</th><td>${escapeHtml(leadExtended.tool || "scanner")}</td></tr>
      <tr><th>Active PoC Status</th><td>${escapeHtml(activePocStatusText(lead.active_poc))}</td></tr>
      <tr><th>Active PoC Command</th><td><code>${escapeHtml(activePocCommandText(lead.active_poc))}</code></td></tr>
    </table>
    <h4>PoC Validation</h4>
    <pre>${escapeHtml(lead.proof_of_concept || "N/A")}</pre>
    <h4>Active PoC Output</h4>
    <pre>${escapeHtml(activePocOutputText(lead.active_poc))}</pre>
    <h4>Instances</h4>
    <table class="results">
      <thead>
        <tr><th>File Path</th><th>Folder</th><th>Line</th><th>Workflow Status</th><th>Tool</th><th>CWE</th><th>OWASP</th></tr>
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
      <td>${escapeHtml(normalizedFindingTitle(finding))}</td>
      <td>${renderCweLink(finding.cwe_id || "N/A")}</td>
      <td>${escapeHtml(finding.owasp_mapping || "N/A")}</td>
      <td>${escapeHtml(workflowStatusText(finding.status))}</td>
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
      <thead><tr><th>File</th><th>Line</th><th>Issue</th><th>CWE</th><th>OWASP</th><th>Workflow Status</th></tr></thead>
      <tbody>${rows || "<tr><td colspan='6' class='muted'>No findings.</td></tr>"}${hiddenRow}</tbody>
    </table>
  </details>`;
    })
    .join("");
  const moduleEvidenceOverflow = Math.max(0, moduleSeverityCatalog.length - 220);
  const hasRiskIntel = Boolean(summaryExtras.risk_intelligence);
  const hasReleaseGate = Object.keys(releaseGateDistribution || {}).length > 0;
  const authTypeRows = (authAbuse?.top_vulnerability_types || [])
    .slice(0, 10)
    .map((row) => `<tr><td>${escapeHtml(String(row.type || "Issue"))}</td><td align="center">${Number(row.count || 0)}</td></tr>`)
    .join("");
  const authFileRows = (authAbuse?.affected_files || [])
    .slice(0, 20)
    .map(
      (row) => `<tr><td>${escapeHtml(String(row.file || "unknown"))}</td><td align="center">${Number(row.count || 0)}</td><td align="center">${Number(row.critical || 0)}</td><td align="center">${Number(row.high || 0)}</td></tr>`,
    )
    .join("");
  const authIssueMappingRows = (authAbuse?.issue_file_mapping || [])
    .slice(0, 20)
    .map(
      (row) => `<tr><td>${escapeHtml(String(row.issue_type || "Issue"))}</td><td>${escapeHtml(String(row.file || "unknown"))}</td><td>${escapeHtml(String(row.folder || "."))}</td><td align="center">${Number(row.count || 0)}</td><td align="center">${Number(row.critical || 0)}</td><td align="center">${Number(row.high || 0)}</td></tr>`,
    )
    .join("");
  const evidenceRows = executionEvidence
    .slice(0, 120)
    .map(
      (row) => `<tr>
    <td>${escapeHtml(row.tool)}</td>
    <td>${escapeHtml(row.status)}</td>
    <td>${escapeHtml(row.timestamp || "N/A")}</td>
    <td class="cmd-cell"><code>${escapeHtml(row.command || "N/A")}</code></td>
    <td align="center">${escapeHtml(row.exitCode)}</td>
    <td align="center">${row.durationMs}</td>
    <td><code>${escapeHtml(row.stdoutHash || "N/A")}</code></td>
    <td><code>${escapeHtml(row.stderrHash || "N/A")}</code></td>
  </tr>`,
    )
    .join("");
  const replayRows = findings
    .slice(0, 120)
    .map((finding) => {
      const replay = finding.evidence_replay_pack;
      return `<tr>
    <td>${escapeHtml(finding.finding_uid || "N/A")}</td>
    <td>${escapeHtml(normalizedFindingTitle(finding))}</td>
    <td>${escapeHtml(String(replay?.tool || replay?.inferred_tool || finding.tool || "N/A"))}</td>
    <td>${escapeHtml(replay?.recorded ? "Yes" : "No")}</td>
    <td><code>${escapeHtml(String(replay?.command || "N/A"))}</code></td>
    <td><code>${escapeHtml(String(replay?.record_sha256 || "N/A"))}</code></td>
  </tr>`;
    })
    .join("");
  const timingBreakdown = collectToolTimingRows(report.toolchain_status || {}, toolchainExecution);
  const timingSummary = summarizeTimingRows(timingBreakdown);
  const timingRows = timingSummary.visible
    .slice(0, 60)
    .map(
      (row) => `<tr>
    <td>${escapeHtml(row.tool)}</td>
    <td>${escapeHtml(row.status)}</td>
    <td align="center">${row.attempted ? "Yes" : "No"}</td>
    <td align="center">${row.durationMs}</td>
    <td align="center">${row.findingsCount}</td>
    <td align="center">${row.errorsCount}</td>
    <td align="center">${row.avgMsPerFinding === null ? "N/A" : Number(row.avgMsPerFinding).toFixed(2)}</td>
  </tr>`,
    )
    .join("");
  const attemptedTimingRows = timingSummary.attempted;
  const attemptedTimingTotalMs = timingSummary.totalDuration;
  const attemptedTimingAvgMs = Number(timingSummary.averageDuration.toFixed(2));
  const timingOmittedNote =
    timingSummary.omitted > 0
      ? `<p class="meta">Omitted ${timingSummary.omitted} analyzer(s) that were unavailable or failed in this scan.</p>`
      : "";
  const ctoUrgentRows = (Array.isArray(ctoBoard.top_5_urgent_risks) ? ctoBoard.top_5_urgent_risks : [])
    .slice(0, 5)
    .map((item) => {
      const row = item as Record<string, unknown>;
      return `<tr>
    <td>${escapeHtml(String(row.title || row.vulnerability_title || "Risk"))}</td>
    <td>${escapeHtml(String(row.severity || "N/A"))}</td>
    <td align="center">${Number(row.priority_score || 0).toFixed(2)}</td>
    <td>${escapeHtml(String(row.business_impact || "N/A"))}</td>
  </tr>`;
    })
    .join("");
  const riskStoryOutcomeRows = objectSummaryRows(riskStory.likely_outcome);
  const maturityMetrics = (advanced.security_maturity_scoring as Record<string, unknown>) || {};
  const maturityRows = objectSummaryRows(maturityMetrics);
  const aiSolutionEngine = (advanced.ai_solution_engine as Record<string, unknown>) || {};
  const findingByUid = new Map(findings.map((finding) => [String(finding.finding_uid || ""), finding]));
  const fixWindowPlanSource =
    Object.keys((advanced.what_should_i_fix_first_ai as Record<string, unknown>) || {}).length > 0
      ? ((advanced.what_should_i_fix_first_ai as Record<string, unknown>) || {})
      : buildFallbackFixWindowPlan(findings);
  const hasMeaningfulFixPlan = Object.values(fixWindowPlanSource).some((value) => {
    if (!Array.isArray(value) || value.length === 0) {
      return false;
    }
    return value.some((entry) => {
      if (typeof entry === "string") {
        const finding = findingByUid.get(entry);
        if (!finding) {
          return false;
        }
        const title = normalizedFindingTitle(finding).trim().toLowerCase();
        return Boolean(String(finding.file_path || "").trim()) && !["", "issue", "unknown", "n/a", "unclassified security finding"].includes(title);
      }
      if (!entry || typeof entry !== "object") {
        return false;
      }
      const raw = entry as Record<string, unknown>;
      const title = String(raw.title || "").trim().toLowerCase();
      const severity = String(raw.severity || "Info");
      const filePath = String(raw.file_path || "").trim();
      const priorityScore = Number(raw.priority_score || 0);
      return Boolean(filePath) && !["", "issue", "unknown", "n/a", "unclassified security finding"].includes(title) && (priorityScore > 0 || ["Critical", "High", "Medium"].includes(severity));
    });
  });
  const fixFirstRows = Object.entries(fixWindowPlanSource)
    .map(([window, value]) => {
      return `<tr><td>${escapeHtml(window.replaceAll("_", " "))}</td><td>${renderFixWindowValue(value, findingByUid)}</td></tr>`;
    })
    .join("");
  const fpCandidates = Array.isArray((falsePositiveReport as Record<string, unknown>).candidates)
    ? ((falsePositiveReport as Record<string, unknown>).candidates as Array<Record<string, unknown>>)
    : [];
  const fpGroupedRows = groupFalsePositiveRows(fpCandidates)
    .slice(0, 80)
    .map(
      (row) => `<tr>
    <td>${escapeHtml(row.issue)}</td>
    <td>${escapeHtml(row.severity)}</td>
    <td>${escapeHtml(row.locations)}</td>
    <td>${escapeHtml(row.reason)}</td>
    <td>${escapeHtml(row.detail)}</td>
    <td align="center">${Number(row.confidence || 0).toFixed(2)}</td>
  </tr>`,
    )
    .join("");
  const cisoRows = (Array.isArray(cisoView.vulnerability_operational_table) ? cisoView.vulnerability_operational_table : [])
    .slice(0, 80)
    .map((item) => {
      const row = item as Record<string, unknown>;
      return `<tr>
    <td>${escapeHtml(String(row.title || "Issue"))}</td>
    <td>${escapeHtml(String(row.severity || "Info"))}</td>
    <td align="center">${Number(row.cvss_score || 0).toFixed(1)}</td>
    <td align="center">${Number(row.exploitability_score || 0).toFixed(2)}</td>
    <td align="center">${Number(row.business_impact_score || 0).toFixed(2)}</td>
    <td align="center">${Number(row.priority_score || 0).toFixed(2)}</td>
    <td>${escapeHtml(String(row.active_exploit_flag ? "Yes" : "No"))}</td>
    <td>${escapeHtml(String(row.release_gate_action || "Track"))}</td>
    <td align="center">${Number(row.sla_hours || 0)}</td>
  </tr>`;
    })
    .join("");
  const devRows = (Array.isArray(devView.tactical_findings) ? devView.tactical_findings : [])
    .slice(0, 40)
    .map((item) => {
      const row = item as Record<string, unknown>;
      return `<tr>
    <td>${escapeHtml(String(row.title || "Issue"))}</td>
    <td>${escapeHtml(String(row.severity || "Info"))}</td>
    <td>${escapeHtml(String(row.file_path || "unknown"))}:${Number(row.line_number || 1)}</td>
    <td>${renderCweLink(String(row.cwe_id || "N/A"))}</td>
    <td>${escapeHtml(String(row.owasp_mapping || "N/A"))}</td>
    <td><pre class="code">${escapeHtml(String(row.secure_fix_snippet || "N/A"))}</pre></td>
  </tr>`;
    })
    .join("");
  const aiSummaryRows = (Array.isArray(ctoBoard.ai_summary_plain_language) ? ctoBoard.ai_summary_plain_language : [])
    .slice(0, 6)
    .map((item) => `<li>${escapeHtml(String(item))}</li>`)
    .join("");
  const fpRows = fpGroupedRows;
  const trendMeta = (ctoBoard.trend as Record<string, unknown>) || {};
  const trendText =
    trendMeta.available === false
      ? "Unavailable (no prior scan in report chain)"
      : `${escapeHtml(String(trendMeta.direction || "stable"))} (delta=${escapeHtml(String(trendMeta.delta_points || 0))})`;
  const financialText = formatBestLikelyWorst((ctoBoard.financial_exposure_usd as Record<string, unknown>) || {});
  const downtimeText = formatBestLikelyWorst((ctoBoard.downtime_estimate as Record<string, unknown>) || {});
  const heroCards = renderStatGrid([
    { label: "Total Findings", value: report.summary.total_findings, tone: "accent", sub: "Deduplicated alert inventory" },
    { label: "Files Impacted", value: report.summary.files_impacted, tone: "low", sub: "Code paths affected in this scan" },
    {
      label: "Critical",
      value: report.summary.severity_distribution?.Critical || 0,
      tone: "critical",
      sub: "Immediate release blockers",
    },
    {
      label: "High",
      value: report.summary.severity_distribution?.High || 0,
      tone: "high",
      sub: "Fix before production",
    },
    {
      label: "Active Risk",
      value: report.summary.active_risk_findings,
      tone: "medium",
      sub: "Critical + High still open",
    },
    {
      label: "Block Release",
      value: releaseGateDistribution["Block release"] || 0,
      tone: "critical",
      sub: "Findings mapped to hard release stop",
    },
    {
      label: "Known Exploited",
      value: riskIntel.known_exploited_findings,
      tone: "info",
      sub: "CISA KEV-backed findings",
    },
  ]);
  const hasEnterpriseData = Boolean(
    enterprise &&
      (Number(enterprise.required_tools_total || 0) > 0 ||
        Number(enterprise.readiness_score || 0) > 0 ||
        Boolean((enterprise.blockers || []).length) ||
        Number(toolchainExecution?.attempted_tools || 0) > 0),
  );
  const hasCtoData = Boolean(
    ctoUrgentRows ||
      aiSummaryRows ||
      financialText !== "N/A" ||
      downtimeText !== "N/A",
  );
  const hasCisoData = Boolean(cisoRows);
  const hasDevData = Boolean(devRows);
  const riskStoryTitle = String(riskStory.scenario_title || "").trim();
  const riskStoryNarrative = String(riskStory.narrative || "").trim();
  const hasRiskStoryData = Boolean(
    riskStoryTitle ||
      (riskStoryNarrative &&
        !["no chained attack story generated.", "n/a"].includes(riskStoryNarrative.toLowerCase())) ||
      riskStoryOutcomeRows,
  );
  const hasMaturityData = Object.values(maturityMetrics).some((value) => Number(value) > 0);
  const hasAdvancedData = Boolean(hasMaturityData || hasMeaningfulFixPlan);
  const hasFalsePositiveData = Boolean(fpRows);
  const hasToolEvidenceData = Boolean(evidenceRows);
  const hasReplayData = hasReplaySummaryData(deterministicReplay);
  const hasIntegrityData = hasIntegrityChainData(reportIntegrity);
  const hasAuthAbuseData = hasMeaningfulAuthAbuse(authAbuse);
  const hasTimingData = Boolean(timingRows);
  const hasRiskIntelData = Boolean(
    (hasRiskIntel && riskIntel && (riskIntel.findings_with_cve || riskIntel.findings_cvss_ge_7 || riskIntel.known_exploited_findings)) ||
      hasReleaseGate ||
      (gitDiffTracking && (gitDiffTracking.enabled || gitDiffTracking.findings_on_changed_files || gitDiffTracking.findings_on_changed_lines)),
  );
  const riskIntelSection = hasRiskIntelData
    ? `<section class="panel">
    <h2>Risk Intelligence and Release Gates</h2>
    <div class="table-scroll">
      <table class="summary">
        <thead><tr><th>Metric</th><th>Value</th></tr></thead>
        <tbody>
        <tr><td>Findings with CVE</td><td align="center">${hasRiskIntel && riskIntel ? riskIntel.findings_with_cve : "0"}</td></tr>
        <tr><td>Findings with CVSS &gt;= 7.0</td><td align="center">${hasRiskIntel && riskIntel ? riskIntel.findings_cvss_ge_7 : "0"}</td></tr>
        <tr><td>Known Exploited Findings (CISA KEV)</td><td align="center">${hasRiskIntel && riskIntel ? riskIntel.known_exploited_findings : "0"}</td></tr>
        <tr><td>Release Gate: Block release</td><td align="center">${hasReleaseGate ? Number(releaseGateDistribution["Block release"] || 0) : "0"}</td></tr>
        <tr><td>Release Gate: Fix before prod</td><td align="center">${hasReleaseGate ? Number(releaseGateDistribution["Fix before prod"] || 0) : "0"}</td></tr>
        <tr><td>Release Gate: Scheduled fix</td><td align="center">${hasReleaseGate ? Number(releaseGateDistribution["Scheduled fix"] || 0) : "0"}</td></tr>
        <tr><td>Release Gate: Track</td><td align="center">${hasReleaseGate ? Number(releaseGateDistribution["Track"] || 0) : "0"}</td></tr>
        <tr><td>Git diff tracking enabled</td><td align="center">${gitDiffTracking?.enabled ? "Yes" : "No"}</td></tr>
        <tr><td>Findings on changed files</td><td align="center">${gitDiffTracking?.findings_on_changed_files || 0}</td></tr>
        <tr><td>Findings on changed lines</td><td align="center">${gitDiffTracking?.findings_on_changed_lines || 0}</td></tr>
        </tbody>
      </table>
    </div>
  </section>`
    : `<section class="panel"><h2>Risk Intelligence and Release Gates</h2><p class="table-note">No risk-intelligence or release-gate artifacts were captured for this scan.</p></section>`;
  const falsePositiveSection = fpRows
    ? `<section class="panel">
    <h2>False Positive Review</h2>
    <p class="muted">${escapeHtml(String((falsePositiveReport as Record<string, unknown>).policy_note || "No false-positive policy note available."))}</p>
    <div class="table-scroll">
      <table>
        <thead><tr><th>Issue</th><th>Severity</th><th>Location(s)</th><th>Reason</th><th>Detail</th><th>Confidence</th></tr></thead>
        <tbody>${fpRows}</tbody>
      </table>
    </div>
  </section>`
    : `<section class="panel"><h2>False Positive Review</h2><p class="table-note">No false-positive candidates were identified for this scan.</p></section>`;
  const toolEvidenceSection = evidenceRows
    ? `<section class="panel">
    <h2>Tool Command Evidence (Authenticity)</h2>
    <p class="muted">Real command execution records captured during scan (safe validation commands, exit code, timing, and output hashes).</p>
    <div class="table-scroll">
      <table id="executionEvidenceTable">
        <thead>
        <tr>
          <th data-sort-index="0" data-sort-type="text">Tool</th>
          <th data-sort-index="1" data-sort-type="text">Status</th>
          <th data-sort-index="2" data-sort-type="text">Timestamp</th>
          <th data-sort-index="3" data-sort-type="text">Command</th>
          <th data-sort-index="4" data-sort-type="number">Exit</th>
          <th data-sort-index="5" data-sort-type="number">Duration (ms)</th>
          <th data-sort-index="6" data-sort-type="text">stdout SHA256</th>
          <th data-sort-index="7" data-sort-type="text">stderr SHA256</th>
        </tr>
        </thead>
        <tbody>${evidenceRows}</tbody>
      </table>
    </div>
  </section>`
    : `<section class="panel"><h2>Tool Command Evidence (Authenticity)</h2><p class="table-note">No tool command evidence was captured for this scan.</p></section>`;
  const replaySectionHtml = hasReplaySummaryData(deterministicReplay)
    ? `<section class="panel">
    <h2>Deterministic Evidence Replay Pack</h2>
    <p class="muted">Finding-level replay metadata derived from captured command evidence (for reproducibility and dispute resolution).</p>
    <div class="table-scroll">
      <table class="summary">
        <thead><tr><th>Metric</th><th>Value</th></tr></thead>
        <tbody>
        <tr><td>Mode</td><td>${escapeHtml(String(deterministicReplay?.mode || "N/A"))}</td></tr>
        <tr><td>Replay Coverage</td><td align="center">${deterministicReplay ? `${Number(deterministicReplay.replay_coverage_percent || 0).toFixed(2)}%` : "N/A"}</td></tr>
        <tr><td>Findings with Replay</td><td align="center">${deterministicReplay ? `${Number(deterministicReplay.findings_with_replay || 0)}/${Number(deterministicReplay.findings_total || 0)}` : "N/A"}</td></tr>
        <tr><td>Evidence Records</td><td align="center">${deterministicReplay ? Number(deterministicReplay.tool_evidence_records || 0) : "N/A"}</td></tr>
        <tr><td>Tools with Evidence</td><td>${deterministicReplay?.tools_with_evidence?.length ? escapeHtml(deterministicReplay.tools_with_evidence.join(", ")) : "N/A"}</td></tr>
      </tbody>
      </table>
    </div>
    <div class="table-scroll">
      <table>
        <thead>
        <tr>
          <th>Finding UID</th>
          <th>Issue</th>
          <th>Tool</th>
          <th>Recorded</th>
          <th>Command</th>
          <th>Record SHA256</th>
        </tr>
        </thead>
        <tbody>${replayRows || "<tr><td colspan='6' class='muted'>No finding-level replay records captured.</td></tr>"}</tbody>
      </table>
    </div>
  </section>`
    : `<section class="panel"><h2>Deterministic Evidence Replay Pack</h2><p class="table-note">No deterministic replay evidence metadata was captured for this scan.</p></section>`;
  const integritySectionHtml = hasIntegrityChainData(reportIntegrity)
    ? `<section class="panel">
    <h2>Tamper-Evident Report Chain</h2>
    <div class="table-scroll">
      <table class="summary">
        <thead><tr><th>Artifact</th><th>Value</th></tr></thead>
        <tbody>
        <tr><td>Chain Version</td><td>${escapeHtml(String(reportIntegrity?.chain_version || "N/A"))}</td></tr>
        <tr><td>Tamper Evident</td><td>${reportIntegrity ? (reportIntegrity.tamper_evident ? "Yes" : "No") : "N/A"}</td></tr>
        <tr><td>Generated At</td><td>${escapeHtml(String(reportIntegrity?.generated_at || "N/A"))}</td></tr>
        <tr><td>Report SHA256</td><td><code>${escapeHtml(String(reportIntegrity?.report_sha256 || "N/A"))}</code></td></tr>
        <tr><td>Findings SHA256</td><td><code>${escapeHtml(String(reportIntegrity?.findings_sha256 || "N/A"))}</code></td></tr>
        <tr><td>Tool Evidence SHA256</td><td><code>${escapeHtml(String(reportIntegrity?.tool_evidence_sha256 || "N/A"))}</code></td></tr>
        <tr><td>Metadata SHA256</td><td><code>${escapeHtml(String(reportIntegrity?.metadata_sha256 || "N/A"))}</code></td></tr>
        <tr><td>Previous Report SHA256</td><td><code>${escapeHtml(String(reportIntegrity?.previous_report_sha256 || "N/A"))}</code></td></tr>
      </tbody>
      </table>
    </div>
  </section>`
    : `<section class="panel"><h2>Tamper-Evident Report Chain</h2><p class="table-note">No report integrity chain metadata was captured for this scan.</p></section>`;

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>CodeSentinelX Vulnerability Report</title>
  <style>${exportThemeCss(`
    .panel{background:linear-gradient(165deg,rgba(17,37,63,0.38),rgba(10,27,46,0.24));border:1px solid rgba(120,168,205,0.32);border-radius:16px;box-shadow:0 12px 28px rgba(0,0,0,0.1);padding:18px;margin-bottom:14px}
    .layout{display:grid;grid-template-columns:1fr 1fr;gap:12px}
    .summary{max-width:620px}
    .results th{width:18%}
    .toolbar{display:flex;gap:8px;align-items:center;margin:6px 0 10px;flex-wrap:wrap}
    input{background:rgba(7,20,36,0.14);border:1px solid rgba(120,168,205,0.28);border-radius:8px;color:var(--text);padding:7px 10px;min-width:240px}
    .chart-wrap{display:grid;grid-template-columns:320px 1fr;gap:12px;align-items:center}
    .legend-item{display:flex;align-items:center;gap:8px;color:var(--muted);margin:6px 0}
    .dot{width:10px;height:10px;border-radius:50%}
    .bars{display:grid;gap:8px}
    .bar-row{display:grid;grid-template-columns:220px 1fr auto;gap:8px;align-items:center}
    .bar-track{height:12px;border:1px solid rgba(120,168,205,0.28);border-radius:999px;background:rgba(7,20,36,0.14);overflow:hidden}
    .bar-fill{height:100%;background:linear-gradient(90deg,#1f88ff,var(--accent))}
    .bar-label{color:var(--muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
    .hidden-section{display:none}
    .alert-link,.drill-link{background:none;border:none;color:var(--accent);cursor:pointer;text-decoration:underline;font:inherit;padding:0}
    .drill-state{margin-bottom:8px;color:var(--muted)}
    .evidence-block{border:1px solid rgba(120,168,205,0.24);border-radius:12px;padding:10px;background:rgba(6,17,29,0.14);margin-bottom:10px}
    .evidence-block summary{cursor:pointer;font-weight:700}
    .cmd-cell{max-width:580px;white-space:normal;word-break:break-all}
    .ai-fix-item{padding:8px 0;border-bottom:1px dashed var(--line)}
    .ai-fix-item:last-child{border-bottom:none}
    #executionEvidenceTable{table-layout:fixed}
    #executionEvidenceTable th,#executionEvidenceTable td{word-break:break-all}
    #executionEvidenceTable th:nth-child(1),#executionEvidenceTable td:nth-child(1){width:7%}
    #executionEvidenceTable th:nth-child(2),#executionEvidenceTable td:nth-child(2){width:8%}
    #executionEvidenceTable th:nth-child(3),#executionEvidenceTable td:nth-child(3){width:12%}
    #executionEvidenceTable th:nth-child(4),#executionEvidenceTable td:nth-child(4){width:31%}
    #executionEvidenceTable th:nth-child(5),#executionEvidenceTable td:nth-child(5){width:5%}
    #executionEvidenceTable th:nth-child(6),#executionEvidenceTable td:nth-child(6){width:8%}
    #executionEvidenceTable th:nth-child(7),#executionEvidenceTable td:nth-child(7){width:14%}
    #executionEvidenceTable th:nth-child(8),#executionEvidenceTable td:nth-child(8){width:15%}
    @media (max-width:1200px){.layout,.chart-wrap{grid-template-columns:1fr}}
  `)}</style>
</head>
<body>
  <main class="report-shell">
  <section class="hero">
    <h1>CodeSentinelX Vulnerability Dashboard</h1>
    <div class="hero-meta">
      <div class="meta-pill"><strong>Target:</strong> ${escapeHtml(report.target_path)}</div>
      <div class="meta-pill"><strong>Generated:</strong> ${escapeHtml(formatDisplayTimestamp(report.generated_at))}</div>
      <div class="meta-pill"><strong>Risk Score:</strong> ${report.summary.risk_score} (${escapeHtml(report.summary.risk_rating)})</div>
      <div class="meta-pill"><strong>Preset:</strong> ${escapeHtml(String(scan.report.executive_summary.scan_preset_label || scan.report.executive_summary.scan_preset || "Standard"))}</div>
    </div>
    <div class="callout" style="margin-top:14px">Board-facing release gating, engineering triage, and finding-level evidence are kept in one export. Use the alert drill-down sections below to move from aggregate risk to exact code locations.</div>
    ${heroCards}
  </section>

  <section class="panel">
    <div class="layout">
      <div>
        <h2>Severity Summary</h2>
        <div class="table-scroll">
          <table id="severitySummary" class="summary">
            <thead><tr><th data-sort-index="0" data-sort-type="text">Risk Level</th><th data-sort-index="1" data-sort-type="number" align="center">Count</th></tr></thead>
            <tbody>${summaryRows}</tbody>
          </table>
        </div>
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
        <div class="table-scroll">
          <table id="owaspTable" class="summary">
            <thead><tr><th data-sort-index="0" data-sort-type="text">OWASP Category</th><th data-sort-index="1" data-sort-type="number" align="center">Count</th></tr></thead>
            <tbody>${owaspRows || "<tr><td colspan='2' class='muted'>No OWASP category data.</td></tr>"}</tbody>
          </table>
        </div>
      </div>
      <div>
        <h3>Top Categories Chart</h3>
        <div id="owaspBars" class="bars"></div>
      </div>
    </div>
  </section>

  ${riskIntelSection}

  ${hasEnterpriseData ? `<section class="panel">
    <h2>Enterprise Assurance</h2>
    <p class="muted">Status meaning: READY=release criteria met, WARNING=partial readiness, BLOCKED=release gate not satisfied.</p>
    <div class="table-scroll">
      <table class="summary">
        <thead><tr><th>Metric</th><th>Value</th></tr></thead>
        <tbody>
        <tr><td>Status</td><td align="center">${escapeHtml(String(enterprise?.status || "blocked").toUpperCase())}</td></tr>
        <tr><td>Readiness Score</td><td align="center">${enterprise?.readiness_score || 0}</td></tr>
        <tr><td>Required Tools Ready</td><td align="center">${enterprise?.required_tools_ready || 0}/${enterprise?.required_tools_total || 0}</td></tr>
        <tr><td>Required Tool Coverage</td><td align="center">${(enterprise?.required_tools_coverage_percent || 0).toFixed(2)}%</td></tr>
        <tr><td>Tool Success Rate</td><td align="center">${(toolchainExecution?.success_rate_percent || 0).toFixed(2)}%</td></tr>
        <tr><td>Attempted Tools</td><td align="center">${toolchainExecution?.attempted_tools || 0}</td></tr>
        <tr><td>Failed Tools</td><td align="center">${toolchainExecution?.failed_tools || 0}</td></tr>
        <tr><td>Recommendation</td><td>${escapeHtml(enterprise?.recommendation || "N/A")}</td></tr>
        </tbody>
      </table>
    </div>
    <h3>Enterprise Blockers</h3>
    <ul>${enterpriseBlockers || "<li class='muted'>No enterprise blockers detected.</li>"}</ul>
  </section>` : ""}

  <section class="panel">
    <h2>Data Quality</h2>
    <div class="table-scroll">
      <table class="summary">
        <thead><tr><th>Metric</th><th>Value</th></tr></thead>
        <tbody>${dataQualityRows}</tbody>
      </table>
    </div>
  </section>

  ${hasCtoData ? `<section class="panel">
    <h2>CTO / Board View</h2>
    <div class="table-scroll">
      <table class="summary">
        <thead><tr><th>Metric</th><th>Value</th></tr></thead>
        <tbody>
        <tr><td>Business Risk Exposure Score</td><td align="center">${formatMetricNumber(ctoBoard.business_risk_exposure_score ?? report.summary.risk_score, 2)}</td></tr>
        <tr><td>Trend</td><td>${trendText}</td></tr>
        <tr><td>Financial Exposure (Best / Likely / Worst USD)</td><td>${financialText}</td></tr>
        <tr><td>Downtime Estimate (Best / Likely / Worst Hours)</td><td>${downtimeText}</td></tr>
        </tbody>
      </table>
    </div>
    <h3>Top 5 Urgent Risks</h3>
    <div class="table-scroll">
      <table>
        <thead><tr><th>Risk</th><th>Severity</th><th>Priority</th><th>Business Impact</th></tr></thead>
        <tbody>${ctoUrgentRows || "<tr><td colspan='4' class='muted'>No urgent risks available.</td></tr>"}</tbody>
      </table>
    </div>
    <h3>AI Executive Summary</h3>
    <ul>${aiSummaryRows || "<li class='muted'>No AI summary bullets available.</li>"}</ul>
  </section>` : ""}

  ${hasCisoData ? `<section class="panel">
    <h2>CISO / Security Team View</h2>
    <p class="muted"><strong>Attack Chain:</strong> ${escapeHtml(String(cisoView.attack_chain_example || "External attacker -> service/API -> lateral movement -> critical asset impact"))}</p>
    <div class="table-scroll">
      <table>
        <thead><tr><th>Issue</th><th>Severity</th><th>CVSS</th><th>Exploitability</th><th>Business Impact</th><th>Priority</th><th>Active Exploit</th><th>Release Gate</th><th>SLA (h)</th></tr></thead>
        <tbody>${cisoRows || "<tr><td colspan='9' class='muted'>No CISO operational rows available.</td></tr>"}</tbody>
      </table>
    </div>
  </section>` : ""}

  ${hasDevData ? `<section class="panel">
    <h2>Developer / DevOps View</h2>
    <div class="table-scroll">
      <table>
        <thead><tr><th>Issue</th><th>Severity</th><th>Location</th><th>CWE</th><th>OWASP</th><th>Secure Fix Snippet</th></tr></thead>
        <tbody>${devRows || "<tr><td colspan='6' class='muted'>No tactical remediation rows available.</td></tr>"}</tbody>
      </table>
    </div>
  </section>` : ""}

  ${hasRiskStoryData ? `<section class="panel">
    <h2>Risk Story Mode</h2>
    <p><strong>Scenario:</strong> ${escapeHtml(String(riskStory.scenario_title || "N/A"))}</p>
    <p>${escapeHtml(String(riskStory.narrative || "No chained attack story generated."))}</p>
    <div class="table-scroll">
      <table class="summary">
        <thead><tr><th>Likely Outcome</th><th>Value</th></tr></thead>
        <tbody>${riskStoryOutcomeRows || "<tr><td colspan='2' class='muted'>No modeled outcomes.</td></tr>"}</tbody>
      </table>
    </div>
  </section>` : ""}

  ${hasAdvancedData ? `<section class="panel">
    <h2>Advanced Features</h2>
    <h3>Security Maturity Scoring</h3>
    <div class="table-scroll">
      <table class="summary">
        <thead><tr><th>Metric</th><th>Value</th></tr></thead>
        <tbody>${maturityRows || "<tr><td colspan='2' class='muted'>No maturity data.</td></tr>"}</tbody>
      </table>
    </div>
    <h3>AI Solution Engine</h3>
    <p class="muted">${escapeHtml(String(aiSolutionEngine.description || "Evidence-driven local remediation engine using finding context, code location, and validation evidence."))}</p>
    <p class="muted"><strong>Mode:</strong> ${escapeHtml(String(aiSolutionEngine.mode || "contextual-remediation"))} | <strong>Provider:</strong> ${escapeHtml(String(aiSolutionEngine.provider || "local-evidence-driven"))} | <strong>Model:</strong> ${escapeHtml(String(aiSolutionEngine.model || "N/A"))} | <strong>Status:</strong> ${escapeHtml(String(aiSolutionEngine.status || "ready"))} | <strong>Grounded:</strong> ${escapeHtml(String(aiSolutionEngine.grounded_generation === false ? "No" : "Yes"))} | <strong>Prioritization:</strong> ${escapeHtml(String(aiSolutionEngine.prioritization_status || "deterministic"))}</p>
    <h3>What Should I Fix First (AI)</h3>
    <div class="table-scroll">
      <table>
        <thead><tr><th>Time Window</th><th>Prioritized Findings</th></tr></thead>
        <tbody>${fixFirstRows || "<tr><td colspan='2' class='muted'>No prioritized fix windows.</td></tr>"}</tbody>
      </table>
    </div>
  </section>` : ""}

  ${hasFalsePositiveData ? falsePositiveSection : ""}

  ${hasToolEvidenceData ? toolEvidenceSection : ""}

  ${hasReplayData ? replaySectionHtml : ""}

  ${hasIntegrityData ? integritySectionHtml : ""}

  ${hasTimingData ? `<section class="panel">
    <h2>Analyzer Runtime Breakdown</h2>
    <p class="muted">Deterministic per-analyzer timings captured from this scan execution.</p>
    <div class="table-scroll">
      <table class="summary">
        <thead><tr><th>Metric</th><th>Value</th></tr></thead>
        <tbody>
        <tr><td>Attempted analyzers</td><td align="center">${attemptedTimingRows.length}</td></tr>
        <tr><td>Total attempted duration (ms)</td><td align="center">${attemptedTimingTotalMs}</td></tr>
        <tr><td>Average attempted duration (ms)</td><td align="center">${attemptedTimingAvgMs.toFixed(2)}</td></tr>
        </tbody>
      </table>
    </div>
    ${timingOmittedNote}
    <div class="table-scroll">
      <table id="timingTable">
        <thead>
        <tr>
          <th data-sort-index="0" data-sort-type="text">Analyzer</th>
          <th data-sort-index="1" data-sort-type="text">Status</th>
          <th data-sort-index="2" data-sort-type="text">Attempted</th>
          <th data-sort-index="3" data-sort-type="number">Duration (ms)</th>
          <th data-sort-index="4" data-sort-type="number">Findings</th>
          <th data-sort-index="5" data-sort-type="number">Errors</th>
          <th data-sort-index="6" data-sort-type="number">Avg ms/Finding</th>
        </tr>
        </thead>
        <tbody>${timingRows || "<tr><td colspan='7' class='muted'>No successful analyzer timing data available for this scan.</td></tr>"}</tbody>
      </table>
    </div>
  </section>` : ""}

  ${hasAuthAbuseData ? `<section class="panel">
    <h2>Auth Abuse &amp; Session Security</h2>
    <p class="muted">Leadership view for auth/session-risk findings (BOLA/BOPLA, brute force, session handling, token/cookie issues).</p>
    <div class="table-scroll">
      <table class="summary">
        <thead><tr><th>Metric</th><th>Value</th></tr></thead>
        <tbody>
        <tr><td>Total Findings</td><td align="center">${authAbuse ? Number(authAbuse.total_findings || 0) : "N/A"}</td></tr>
        <tr><td>Critical</td><td align="center">${authAbuse ? Number(authAbuse.severity_distribution?.Critical || 0) : "N/A"}</td></tr>
        <tr><td>High</td><td align="center">${authAbuse ? Number(authAbuse.severity_distribution?.High || 0) : "N/A"}</td></tr>
        <tr><td>Medium</td><td align="center">${authAbuse ? Number(authAbuse.severity_distribution?.Medium || 0) : "N/A"}</td></tr>
        </tbody>
      </table>
    </div>
    <div class="layout">
      <div>
        <h3>Top Auth/Session Issue Types</h3>
        <div class="table-scroll">
          <table>
            <thead><tr><th>Issue Type</th><th>Count</th></tr></thead>
            <tbody>${authTypeRows || "<tr><td colspan='2' class='muted'>No auth/session findings.</td></tr>"}</tbody>
          </table>
        </div>
      </div>
      <div>
        <h3>Most Affected Files</h3>
        <div class="table-scroll">
          <table>
            <thead><tr><th>File</th><th>Total</th><th>Critical</th><th>High</th></tr></thead>
            <tbody>${authFileRows || "<tr><td colspan='4' class='muted'>No affected files.</td></tr>"}</tbody>
          </table>
        </div>
      </div>
    </div>
    <h3>Issue-to-File Mapping</h3>
    <div class="table-scroll">
      <table id="authMappingTable">
        <thead><tr><th data-sort-index="0" data-sort-type="text">Issue Type</th><th data-sort-index="1" data-sort-type="text">File</th><th data-sort-index="2" data-sort-type="text">Folder</th><th data-sort-index="3" data-sort-type="number">Total</th><th data-sort-index="4" data-sort-type="number">Critical</th><th data-sort-index="5" data-sort-type="number">High</th></tr></thead>
        <tbody>${authIssueMappingRows || "<tr><td colspan='6' class='muted'>No auth/session issue mapping available.</td></tr>"}</tbody>
      </table>
    </div>
  </section>` : ""}

  <section class="panel">
    <h2>Affected Modules</h2>
    <div class="toolbar"><input id="moduleSearch" type="search" placeholder="Search module (click severity counts for exact issues)" /></div>
    <div class="table-scroll">
      <table id="moduleTable">
        <thead><tr><th data-sort-index="0" data-sort-type="text">Module</th><th data-sort-index="1" data-sort-type="number">Total</th><th data-sort-index="2" data-sort-type="number">Critical</th><th data-sort-index="3" data-sort-type="number">High</th></tr></thead>
        <tbody>${moduleRows || "<tr><td colspan='4' class='muted'>No affected modules.</td></tr>"}</tbody>
      </table>
    </div>
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
    <p class="muted">Workflow Status: Open = pending triage/remediation, Reviewed = triaged by analyst.</p>
    <table id="drillTable">
      <thead><tr><th>Severity</th><th>Issue</th><th>File</th><th>Module</th><th>Line</th><th>CWE</th><th>OWASP</th><th>Workflow Status</th></tr></thead>
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
          var cweCell = item.cwe_url
            ? "<a href='" + escapeCell(item.cwe_url) + "' target='_blank' rel='noopener noreferrer'>" + escapeCell(item.cwe) + "</a>"
            : escapeCell(item.cwe);
          return "<tr>"
            + "<td>" + escapeCell(item.severity) + "</td>"
            + "<td>" + escapeCell(item.issue) + "</td>"
            + "<td>" + escapeCell(item.file) + "</td>"
            + "<td>" + escapeCell(item.module) + "</td>"
            + "<td align='center'>" + item.line + "</td>"
            + "<td>" + cweCell + "</td>"
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
      initTable("authMappingTable");
      initTable("fileTable", "fileSearch");
      initTable("executionEvidenceTable");
      initTable("timingTable");
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
  const fixQueueLimit = Math.max(120, Number(process.env.USS_FIX_REPORT_QUEUE_LIMIT || 1200));
  const queueFindings = findings.slice(0, fixQueueLimit);
  const detailFindings = queueFindings;
  const enterprise = resolveEnterpriseAssurance(scan, report.summary);
  const toolchainExecution = resolveToolchainExecution(scan, report.summary);
  const dataQualityRaw = report.summary.data_quality || scan.report.executive_summary.data_quality || null;
  const dataQuality =
    dataQualityRaw && Object.keys(dataQualityRaw).length > 0
      ? dataQualityRaw
      : deriveDataQuality(report.summary, scan.report.executive_summary, findings, toolchainExecution);
  const deterministicReplay =
    report.summary.deterministic_replay ||
    report.deterministic_replay ||
    scan.report.executive_summary.deterministic_replay ||
    null;
  const reportIntegrity =
    report.summary.report_integrity_chain ||
    report.report_integrity_chain ||
    scan.report.executive_summary.report_integrity_chain ||
    null;
  const replayRows = findings
    .filter((finding) => {
      const replay = finding.evidence_replay_pack;
      return Boolean(replay && (replay.recorded || replay.command || replay.record_sha256));
    })
    .slice(0, 80)
    .map((finding) => {
      const replay = finding.evidence_replay_pack || {};
      return `<tr>
    <td><code>${escapeHtml(finding.finding_uid)}</code></td>
    <td>${escapeHtml(normalizedFindingTitle(finding))}</td>
    <td>${escapeHtml(String(replay.tool || "N/A"))}</td>
    <td>${replay.recorded ? "Yes" : "No"}</td>
    <td><code>${escapeHtml(String(replay.command || "N/A"))}</code></td>
    <td><code>${escapeHtml(String(replay.record_sha256 || "N/A"))}</code></td>
  </tr>`;
    })
    .join("");

  const severityRows = SEVERITY_ORDER.map((severity) => {
    const count = report.summary.severity_distribution?.[severity] || 0;
    return `<tr><td>${severity}</td><td align="center">${count}</td></tr>`;
  }).join("");
  const dataQualityRows = dataQuality
    ? `
      <tr><td>Raw Findings</td><td>${Number(dataQuality.raw_findings || 0)}</td></tr>
      <tr><td>Deduplicated Findings</td><td>${Number(dataQuality.deduplicated_findings || 0)}</td></tr>
      <tr><td>Duplicates Removed</td><td>${Number(dataQuality.duplicate_findings_removed || 0)} (${Number(dataQuality.dedup_ratio_percent || 0).toFixed(2)}%)</td></tr>
      <tr><td>Suppressed Findings</td><td>${Number(dataQuality.suppressed_findings || 0)} (${Number(dataQuality.suppression_rate_percent || 0).toFixed(2)}%)</td></tr>
      <tr><td>Tool Success Rate</td><td>${Number(dataQuality.tool_success_rate_percent || 0).toFixed(2)}%</td></tr>
      <tr><td>Coverage Confidence</td><td>${escapeHtml(String(dataQuality.coverage_confidence || "N/A"))} (${Number(dataQuality.coverage_confidence_score || 0).toFixed(1)})</td></tr>
      <tr><td>Unknown Rule IDs</td><td>${Number(dataQuality.unknown_rule_count || 0)}</td></tr>
      <tr><td>Unknown CWE</td><td>${Number(dataQuality.unknown_cwe_count || 0)}</td></tr>
      <tr><td>Unknown OWASP</td><td>${Number(dataQuality.unknown_owasp_count || 0)}</td></tr>
      <tr><td>Findings with Taxonomy Gaps</td><td>${Number(dataQuality.unknown_taxonomy_count || 0)}</td></tr>
    `
    : `<tr><td colspan="2" class="muted">No data quality metrics available.</td></tr>`;
  const fixVerificationSummary = normalizedFixVerificationSummary(report.summary.fix_verification, findings);
  const severityBars = renderMetricBars(
    "Severity Mix",
    SEVERITY_ORDER.map((severity) => ({
      label: severity,
      value: Number(report.summary.severity_distribution?.[severity] || 0),
      tone:
        severity === "Critical"
          ? "critical"
          : severity === "High"
            ? "high"
            : severity === "Medium"
              ? "medium"
              : severity === "Low"
                ? "low"
                : "info",
    })),
  );
  const verificationBars = renderMetricBars(
    "Fix Verification Mix",
    [
      { label: "Performed", value: Number(fixVerificationSummary.performed || 0), tone: "accent" },
      { label: "Verified Fixed", value: Number(fixVerificationSummary.verified_fixed || 0), tone: "info" },
      { label: "Verification Failed", value: Number(fixVerificationSummary.verification_failed || 0), tone: "critical" },
      { label: "Inconclusive", value: Number(fixVerificationSummary.inconclusive || 0), tone: "medium" },
      { label: "Build Passed", value: Number(fixVerificationSummary.build_verified || 0), tone: "info" },
      { label: "Build Failed", value: Number(fixVerificationSummary.build_failed || 0), tone: "critical" },
      { label: "Tests Passed", value: Number(fixVerificationSummary.test_verified || 0), tone: "info" },
      { label: "Tests Failed", value: Number(fixVerificationSummary.test_failed || 0), tone: "critical" },
      { label: "Not Applicable", value: Number(fixVerificationSummary.not_applicable || 0), tone: "low" },
      { label: "Skipped", value: Number(fixVerificationSummary.skipped || 0), tone: "low" },
    ],
  );
  const verificationNote =
    Number(fixVerificationSummary.performed || 0) === 0
      ? "<p class='table-note'>No post-fix verification was executed in this scan. Active PoC sections below are pre-fix validation evidence only.</p>"
      : "";
  const verificationSection =
    Number(fixVerificationSummary.performed || 0) > 0
      ? `<div class="table-scroll">
              <table>
                <thead><tr><th>Metric</th><th>Value</th></tr></thead>
                <tbody>
                <tr><td>Performed</td><td align="center">${fixVerificationSummary.performed}</td></tr>
                <tr><td>Verified Fixed</td><td align="center">${fixVerificationSummary.verified_fixed}</td></tr>
                <tr><td>Verification Failed</td><td align="center">${fixVerificationSummary.verification_failed}</td></tr>
                <tr><td>Inconclusive</td><td align="center">${fixVerificationSummary.inconclusive}</td></tr>
                <tr><td>Workspace Build Passed</td><td align="center">${fixVerificationSummary.build_verified}</td></tr>
                <tr><td>Workspace Build Failed</td><td align="center">${fixVerificationSummary.build_failed}</td></tr>
                <tr><td>Workspace Tests Passed</td><td align="center">${fixVerificationSummary.test_verified}</td></tr>
                <tr><td>Workspace Tests Failed</td><td align="center">${fixVerificationSummary.test_failed}</td></tr>
                <tr><td>Not Applicable</td><td align="center">${fixVerificationSummary.not_applicable}</td></tr>
                <tr><td>Skipped</td><td align="center">${fixVerificationSummary.skipped}</td></tr>
                </tbody>
              </table>
            </div>
            <div style="padding:10px 14px 14px">${verificationBars}${verificationNote}</div>`
      : `<div style="padding:10px 14px 14px">${verificationNote || "<p class='table-note'>No fix-verification telemetry was captured for this scan.</p>"}</div>`;

  const rows = queueFindings
    .map(
      (finding, index) => `<tr>
    <td>${index + 1}</td>
    <td><span class="sev sev-${finding.severity}">${escapeHtml(finding.severity)}</span></td>
    <td>${escapeHtml(normalizedFindingTitle(finding))}</td>
    <td>${escapeHtml(normalizePath(finding.file_path))}</td>
    <td align="center">${finding.line_number || 1}</td>
    <td>${renderCvssLink(finding.cvss_score)}</td>
    <td>${renderCweLink(finding.cwe_id || "N/A")}</td>
    <td>${escapeHtml(finding.owasp_mapping || "N/A")}</td>
    <td><a class="fix-link" href="#fix-${escapeHtml(finding.finding_uid)}">Open</a></td>
  </tr>`,
    )
    .join("");

  const detailSections = detailFindings
    .map((finding) => {
      const activeStatus = String(finding.active_poc?.status || "").toLowerCase();
      const advisoryLinks = renderAdvisoryLinks(finding);
      const activeOutput =
        activeStatus && activeStatus !== "skipped"
          ? activePocOutputText(finding.active_poc)
          : "Active PoC output is omitted for skipped/not-executed checks to keep this report compact.";
      return `<section id="fix-${escapeHtml(finding.finding_uid)}" class="fix-detail avoid-break">
    <h3>[${escapeHtml(finding.severity)}] ${escapeHtml(normalizedFindingTitle(finding))}</h3>
    <p><strong>Location:</strong> ${escapeHtml(normalizePath(finding.file_path))}:${finding.line_number || 1}</p>
    <p><strong>CWE:</strong> ${renderCweLink(finding.cwe_id || "N/A")} | <strong>OWASP:</strong> ${escapeHtml(finding.owasp_mapping || "N/A")} | <strong>CVSS:</strong> ${renderCvssLink(finding.cvss_score)}</p>
    ${advisoryLinks ? `<p><strong>CVE / Advisory IDs:</strong> ${advisoryLinks}</p>` : ""}
    <p><strong>Recommendation:</strong> ${escapeHtml(finding.recommendation || "N/A")}</p>
    ${dependencyAuthenticitySummary(finding) ? `<p><strong>Dependency Authenticity:</strong> ${escapeHtml(dependencyAuthenticitySummary(finding))}<br><span class="muted">${escapeHtml(dependencyAuthenticityDetail(finding))}</span></p>` : ""}
    <p><strong>Attack Scenario:</strong> ${escapeHtml(finding.attack_scenario || "N/A")}</p>
    <p><strong>Exploitation Path:</strong> ${escapeHtml(finding.exploitation_example || "N/A")}</p>
    <h4>PoC Validation</h4>
    <pre>${escapeHtml(truncateForReport(finding.proof_of_concept || "N/A", 2200))}</pre>
    <p><strong>Active PoC Status:</strong> ${escapeHtml(activePocStatusText(finding.active_poc))}</p>
    <p><strong>Active PoC Command:</strong> <code>${escapeHtml(activePocCommandText(finding.active_poc))}</code></p>
    <h4>Active PoC Output</h4>
    <pre>${escapeHtml(truncateForReport(activeOutput, 1600))}</pre>
    <h4>Fix Verification</h4>
    <p><strong>Result:</strong> ${escapeHtml(fixVerificationResultText(finding.fix_verification))}</p>
    <p><strong>Reason:</strong> ${escapeHtml(fixVerificationReasonText(finding.fix_verification))}</p>
    <p><strong>Post-Fix Command:</strong> <code>${escapeHtml(String(finding.fix_verification?.post_fix_execution?.command || "No post-fix verification command was executed for this finding in this scan."))}</code></p>
    <h4>Post-Fix Output</h4>
    <pre>${escapeHtml(truncateForReport(String(finding.fix_verification?.post_fix_execution?.output || "No post-fix verification output was captured for this finding in this scan."), 1600))}</pre>
    ${
      finding.fix_verification?.build_verification
        ? `<p><strong>Workspace Build Command:</strong> <code>${escapeHtml(String(finding.fix_verification.build_verification.command || "N/A"))}</code></p>
    <pre>${escapeHtml(truncateForReport(String(finding.fix_verification.build_verification.output || "No build output captured."), 1200))}</pre>`
        : ""
    }
    ${
      finding.fix_verification?.test_verification
        ? `<p><strong>Workspace Test Command:</strong> <code>${escapeHtml(String(finding.fix_verification.test_verification.command || "N/A"))}</code></p>
    <pre>${escapeHtml(truncateForReport(String(finding.fix_verification.test_verification.output || "No test output captured."), 1200))}</pre>`
        : ""
    }
    <div class="code-grid">
      <div>
        <h4>Original Code</h4>
        <pre>${escapeHtml(truncateForReport(finding.original_code || "Snippet unavailable.", 1200))}</pre>
      </div>
    <div>
      <h4>${escapeHtml(fixArtifactLabel(finding))}</h4>
      <pre>${escapeHtml(truncateForReport(preferredFindingFix(finding), 1200))}</pre>
    </div>
    </div>
    <h4>AI Remediation Summary</h4>
    <pre>${escapeHtml(truncateForReport(resolvedAiRemediationSummary(finding), 1200))}</pre>
    <p><strong>AI Fix Confidence:</strong> ${escapeHtml(aiFixConfidenceLabel(finding))} (${aiFixConfidenceScore(finding).toFixed(2)}) | <strong>Grounded:</strong> ${escapeHtml(aiGroundingStatus(finding))} | <strong>Source:</strong> ${escapeHtml(String(finding.ai_fix_source || "local-evidence-driven:evidence-rules-v1"))}</p>
    <p><strong>Grounding Notes:</strong> ${escapeHtml(aiGroundingNotes(finding))}</p>
    <h4>AI Validation Steps</h4>
    <pre>${escapeHtml(truncateForReport(resolvedAiValidationSteps(finding), 1200))}</pre>
    ${
      fixArtifactKind(finding) === "exact_patch" && String(finding.patch_preview || "").trim()
        ? `<h4>Patch Preview</h4>
    <pre>${escapeHtml(truncateForReport(finding.patch_preview || "No patch preview available.", 1400))}</pre>`
        : "<p class='table-note'><strong>Patch Preview:</strong> Guidance-only remediation does not include an exact patch.</p>"
    }
  </section>`;
    })
    .join("");
  const enterpriseBlockers = (enterprise?.blockers || [])
    .slice(0, 12)
    .map((item) => `<li>${escapeHtml(item)}</li>`)
    .join("");

  const fixesCards = renderStatGrid([
    {
      label: "Total Findings",
      value: Number(report.summary.total_findings || findings.length),
      tone: "accent",
      sub: "Findings included in remediation review for this export",
    },
    {
      label: "Verified Fixed",
      value: fixVerificationSummary.verified_fixed,
      tone: "info",
      sub: "Post-fix verification passed in this scan",
    },
    {
      label: "Verification Failed",
      value: fixVerificationSummary.verification_failed,
      tone: "critical",
      sub: "Issue still reproduced after the attempted fix",
    },
    {
      label: "Inconclusive",
      value: fixVerificationSummary.inconclusive,
      tone: "medium",
      sub: "More evidence is needed before closing the issue",
    },
    {
      label: "Tool Success Rate",
      value: `${(toolchainExecution?.success_rate_percent || 0).toFixed(1)}%`,
      tone: "low",
      sub: `${toolchainExecution?.successful_tools || 0}/${toolchainExecution?.attempted_tools || 0} analyzers completed`,
    },
  ]);
  const replaySection = hasReplaySummaryData(deterministicReplay)
    ? `<section class="section">
      <div class="table-frame">
        <h2 style="padding:12px 14px 0">Deterministic Evidence Replay Pack</h2>
        <div class="table-scroll">
          <table class="summary">
            <thead><tr><th>Metric</th><th>Value</th></tr></thead>
            <tbody>
            <tr><td>Mode</td><td>${escapeHtml(String(deterministicReplay?.mode || "deterministic-evidence-replay"))}</td></tr>
            <tr><td>Replay Coverage</td><td>${deterministicReplay ? `${Number(deterministicReplay.replay_coverage_percent || 0).toFixed(2)}%` : "N/A"}</td></tr>
            <tr><td>Findings with Replay</td><td>${deterministicReplay ? `${Number(deterministicReplay.findings_with_replay || 0)}/${Number(deterministicReplay.findings_total || 0)}` : "N/A"}</td></tr>
            <tr><td>Evidence Records</td><td>${deterministicReplay ? Number(deterministicReplay.tool_evidence_records || 0) : "N/A"}</td></tr>
            <tr><td>Tools with Evidence</td><td>${deterministicReplay?.tools_with_evidence?.length ? escapeHtml(deterministicReplay.tools_with_evidence.join(", ")) : "N/A"}</td></tr>
            </tbody>
          </table>
        </div>
        <div class="table-scroll">
          <table>
            <thead><tr><th>Finding UID</th><th>Issue</th><th>Tool</th><th>Recorded</th><th>Command</th><th>Record SHA256</th></tr></thead>
            <tbody>${replayRows || "<tr><td colspan='6' class='muted'>No finding-level replay rows available.</td></tr>"}</tbody>
          </table>
        </div>
      </div>
    </section>`
    : `<section class="section"><div class="table-frame"><h2 style="padding:12px 14px 0">Deterministic Evidence Replay Pack</h2><p class="table-note">No deterministic replay evidence metadata was captured for this scan.</p></div></section>`;
  const integritySection = hasIntegrityChainData(reportIntegrity)
    ? `<section class="section">
      <div class="table-frame">
        <h2 style="padding:12px 14px 0">Tamper-Evident Report Chain</h2>
        <div class="table-scroll">
          <table class="summary">
            <thead><tr><th>Artifact</th><th>Value</th></tr></thead>
            <tbody>
            <tr><td>Chain Version</td><td>${escapeHtml(String(reportIntegrity?.chain_version || "1.0"))}</td></tr>
            <tr><td>Tamper Evident</td><td>${reportIntegrity?.tamper_evident ? "Yes" : "No"}</td></tr>
            <tr><td>Generated At</td><td>${escapeHtml(String(reportIntegrity?.generated_at || "N/A"))}</td></tr>
            <tr><td>Report SHA256</td><td><code>${escapeHtml(String(reportIntegrity?.report_sha256 || "N/A"))}</code></td></tr>
            <tr><td>Findings SHA256</td><td><code>${escapeHtml(String(reportIntegrity?.findings_sha256 || "N/A"))}</code></td></tr>
            <tr><td>Tool Evidence SHA256</td><td><code>${escapeHtml(String(reportIntegrity?.tool_evidence_sha256 || "N/A"))}</code></td></tr>
            <tr><td>Metadata SHA256</td><td><code>${escapeHtml(String(reportIntegrity?.metadata_sha256 || "N/A"))}</code></td></tr>
            <tr><td>Previous Report SHA256</td><td><code>${escapeHtml(String(reportIntegrity?.previous_report_sha256 || "N/A"))}</code></td></tr>
          </tbody>
          </table>
        </div>
      </div>
    </section>`
    : `<section class="section"><div class="table-frame"><h2 style="padding:12px 14px 0">Tamper-Evident Report Chain</h2><p class="table-note">No report integrity chain metadata was captured for this scan.</p></div></section>`;

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>CodeSentinelX Original and Suggested Fix Report</title>
  <style>${exportThemeCss(".fix-link{color:var(--accent);text-decoration:underline}.toolbar{display:flex;gap:8px;align-items:center;margin:6px 0 10px;flex-wrap:wrap}input{background:rgba(7,20,36,.14);border:1px solid rgba(120,168,205,.28);border-radius:8px;color:var(--text);padding:7px 10px;min-width:300px}.fix-detail{border:1px solid rgba(120,168,205,.24);border-radius:14px;background:rgba(8,21,36,.14);padding:14px;margin-bottom:12px}.fix-detail h3{margin-bottom:10px}")}</style>
</head>
<body>
  <main class="report-shell">
    <section class="hero">
      <h1>CodeSentinelX Original and Suggested Fix Report</h1>
      <div class="hero-meta">
        <div class="meta-pill"><strong>Target:</strong> ${escapeHtml(report.target_path)}</div>
        <div class="meta-pill"><strong>Generated:</strong> ${escapeHtml(formatDisplayTimestamp(report.generated_at))}</div>
        <div class="meta-pill"><strong>Enterprise Status:</strong> ${escapeHtml(String(enterprise?.status || "blocked").toUpperCase())}</div>
      </div>
      ${fixesCards}
      <div class="callout" style="margin-top:14px">
        <strong>Remediation workflow:</strong> Use the queue for prioritization, then move into the detailed sections for exact code evidence, suggested fixes, PoC evidence, and post-fix verification.
      </div>
    </section>

    <section class="section">
      <div class="section-grid">
        <div class="stack">
          <div class="table-frame">
            <h2 style="padding:12px 14px 0">Severity Summary</h2>
            <div class="table-scroll">
              <table id="severityTable">
                <thead><tr><th data-sort-index="0" data-sort-type="text">Severity</th><th data-sort-index="1" data-sort-type="number">Count</th></tr></thead>
                <tbody>${severityRows}</tbody>
              </table>
            </div>
            <div style="padding:10px 14px 14px">${severityBars}</div>
          </div>
          <div class="table-frame">
            <h2 style="padding:12px 14px 0">${Number(fixVerificationSummary.performed || 0) > 0 ? "Fix Verification Summary" : "Fix Verification Status"}</h2>
            ${verificationSection}
          </div>
        </div>
        <div class="stack">
          <div class="table-frame">
            <h2 style="padding:12px 14px 0">Enterprise Assurance</h2>
            <div class="table-scroll">
              <table>
                <thead><tr><th>Metric</th><th>Value</th></tr></thead>
                <tbody>
                <tr><td>Status</td><td>${escapeHtml(String(enterprise?.status || "blocked").toUpperCase())}</td></tr>
                <tr><td>Readiness Score</td><td>${enterprise?.readiness_score || 0}</td></tr>
                <tr><td>Required Tool Coverage</td><td>${(enterprise?.required_tools_coverage_percent || 0).toFixed(2)}%</td></tr>
                <tr><td>Tool Success Rate</td><td>${(toolchainExecution?.success_rate_percent || 0).toFixed(2)}%</td></tr>
                <tr><td>Recommendation</td><td>${escapeHtml(enterprise?.recommendation || "N/A")}</td></tr>
                </tbody>
              </table>
            </div>
            <div style="padding:0 14px 14px">
              <h3>Enterprise Blockers</h3>
              <ul>${enterpriseBlockers || "<li class='muted'>No enterprise blockers detected.</li>"}</ul>
            </div>
          </div>
          <div class="table-frame">
            <h2 style="padding:12px 14px 0">Data Quality</h2>
            <div class="table-scroll">
              <table>
                <thead><tr><th>Metric</th><th>Value</th></tr></thead>
                <tbody>${dataQualityRows}</tbody>
              </table>
            </div>
          </div>
        </div>
      </div>
    </section>

    <section class="section">
      <div class="table-frame">
        <h2 style="padding:12px 14px 0">Fix Queue</h2>
        <div class="toolbar" style="padding:0 14px 8px"><input id="fixSearch" type="search" placeholder="Search by issue, file, CWE, OWASP" /></div>
      <div class="table-scroll">
          <table id="fixTable">
            <thead><tr><th data-sort-index="0" data-sort-type="number">#</th><th data-sort-index="1" data-sort-type="text">Severity</th><th data-sort-index="2" data-sort-type="text">Issue</th><th data-sort-index="3" data-sort-type="text">File</th><th data-sort-index="4" data-sort-type="number">Line</th><th data-sort-index="5" data-sort-type="number">CVSS</th><th data-sort-index="6" data-sort-type="text">CWE</th><th data-sort-index="7" data-sort-type="text">OWASP</th><th>Details</th></tr></thead>
            <tbody>${rows || "<tr><td colspan='9'>No findings available.</td></tr>"}</tbody>
          </table>
        </div>
      </div>
      <p class="table-note">This queue is intentionally compact for triage. Showing ${queueFindings.length} of ${findings.length} findings. Use filters and exports for full evidence.</p>
    </section>

    ${replaySection}

    ${integritySection}

    <section class="section">
      <h2>Original and Suggested Fix Details</h2>
      ${detailSections || "<p>No fix entries found.</p>"}
      ${findings.length > detailFindings.length ? `<p class="table-note">${findings.length - detailFindings.length} additional finding details were omitted for report readability.</p>` : ""}
    </section>
  </main>
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

function renderFindingDetailsHtml(scan: ScanView): string {
  const findings = sortedFindings(scan.report.vulnerability_fixed_code_report.findings || []);
  const report = scan.report.vulnerability_fixed_code_report;
  const rows = findings
    .map(
      (item) => `<tr>
        <td>${escapeHtml(normalizedFindingTitle(item))}</td>
        <td>${escapeHtml(item.severity)}</td>
        <td>${escapeHtml(`${normalizePath(item.file_path)}:${item.line_number || 1}`)}</td>
        <td>${escapeHtml(item.description || item.business_impact || "N/A")}</td>
        <td>${escapeHtml(preferredFindingFix(item))}</td>
      </tr>`,
    )
    .join("");

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>CodeSentinelX Finding Details Report</title>
  <style>${exportThemeCss()}</style>
</head>
<body>
  <div class="report-shell">
    <section class="hero">
      <h1>CodeSentinelX Finding Details Report</h1>
      <p class="meta"><strong>Target:</strong> ${escapeHtml(report.target_path)}</p>
      <p class="meta"><strong>Generated:</strong> ${escapeHtml(formatDisplayTimestamp(report.generated_at))}</p>
      <p class="meta"><strong>Total Findings:</strong> ${findings.length}</p>
    </section>
    <section class="section">
      <h2>Finding Details</h2>
      <div class="table-frame table-scroll">
        <table id="findingDetailsTable">
          <thead>
            <tr>
              <th width="24%">Finding Details</th>
              <th width="8%">Severity</th>
              <th width="16%">Location</th>
              <th width="29%">Issue Description</th>
              <th width="23%">Remediation</th>
            </tr>
          </thead>
          <tbody>${rows || '<tr><td colspan="5">No findings available.</td></tr>'}</tbody>
        </table>
      </div>
    </section>
  </div>
</body>
</html>`;
}

function renderCombinedHtml(scan: ScanView): string {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>CodeSentinelX Combined Report</title>
  <style>${exportThemeCss(".card{max-width:980px;margin:0 auto}")}</style>
</head>
<body>
  <div class="card hero">
    <h1>CodeSentinelX Combined Security Report</h1>
    <div class="hero-meta">
      <div class="meta-pill"><strong>Target:</strong> ${escapeHtml(scan.report.executive_summary.target_path)}</div>
      <div class="meta-pill"><strong>Risk Score:</strong> ${scan.report.executive_summary.risk_score} (${escapeHtml(scan.report.executive_summary.risk_rating)})</div>
      <div class="meta-pill"><strong>Guidance:</strong> Export dedicated reports for evidence-level detail</div>
    </div>
    <div class="callout" style="margin-top:14px">For full evidence, export separate Existing Security, Vulnerability, and Original/Suggested Fix reports. The combined export is intended only as a cover page and routing layer.</div>
  </div>
</body>
</html>`;
}

function sortedFindings(findings: VulnerabilityFinding[]): VulnerabilityFinding[] {
  const deduped = deduplicatedFindings(findings);
  return deduped.sort((a, b) => {
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

function deduplicatedFindings(findings: VulnerabilityFinding[]): VulnerabilityFinding[] {
  const dedupMap = new Map<string, VulnerabilityFinding>();

  for (const finding of findings || []) {
    const title = normalizedFindingTitle(finding).toLowerCase();
    const path = normalizePath(finding.file_path || "");
    const rule = String(finding.rule_id || "").toLowerCase();
    const cves = cveValues(finding.cve_ids || []).join(",");
    const cwe = String(finding.cwe_id || "").toUpperCase();
    const isDependencyLike =
      title.includes("dependency") ||
      String(finding.owasp_mapping || "").toLowerCase().includes("a06:") ||
      rule.startsWith("trivy-") ||
      rule.startsWith("grype-") ||
      rule.includes("cve-") ||
      cves.length > 0;

    const key = isDependencyLike
      ? `dep::${path}::${title}::${cves || cwe || rule}`
      : `std::${path}::${Number(finding.line_number || 0)}::${title}::${singleLine(String(finding.original_code || (finding as VulnerabilityFinding & { vulnerable_code_snippet?: string }).vulnerable_code_snippet || "")).toLowerCase()}`;

    const existing = dedupMap.get(key);
    if (!existing) {
      dedupMap.set(key, { ...finding, vulnerability_title: normalizedFindingTitle(finding) });
      continue;
    }
    const existingRank = SEVERITY_ORDER.indexOf(existing.severity);
    const incomingRank = SEVERITY_ORDER.indexOf(finding.severity);
    if (incomingRank < existingRank || (finding.cvss_score || 0) > (existing.cvss_score || 0)) {
      dedupMap.set(key, { ...finding, vulnerability_title: normalizedFindingTitle(finding) });
    }
  }

  return [...dedupMap.values()];
}

function normalizedFindingTitle(finding: VulnerabilityFinding): string {
  const raw = String(finding.vulnerability_title || finding.vulnerability_type || "").trim();
  const lower = raw.toLowerCase();
  if (raw && !["security", "security issue", "vulnerability", "issue", "finding"].includes(lower)) {
    return raw;
  }

  const cwe = String(finding.cwe_id || "").toUpperCase();
  const cweMap: Record<string, string> = {
    "CWE-89": "SQL Injection",
    "CWE-78": "Command Injection",
    "CWE-79": "Cross-Site Scripting (XSS)",
    "CWE-22": "Path Traversal",
    "CWE-502": "Insecure Deserialization",
    "CWE-327": "Weak Cryptography Usage",
    "CWE-798": "Hardcoded Secrets / Credentials",
    "CWE-918": "Server-Side Request Forgery (SSRF)",
  };
  if (cweMap[cwe]) {
    return cweMap[cwe];
  }

  const blob = [
    finding.rule_id,
    finding.owasp_mapping,
    finding.description,
    finding.business_impact,
    (finding as VulnerabilityFinding & { vulnerable_code_snippet?: string }).vulnerable_code_snippet,
    finding.original_code,
  ]
    .map((value) => String(value || "").toLowerCase())
    .join(" ");
  const hints: Array<[string, string]> = [
    ["sql injection", "SQL Injection"],
    ["command injection", "Command Injection"],
    ["xss", "Cross-Site Scripting (XSS)"],
    ["cross-site scripting", "Cross-Site Scripting (XSS)"],
    ["path traversal", "Path Traversal"],
    ["hardcoded", "Hardcoded Secrets / Credentials"],
    ["secret", "Hardcoded Secrets / Credentials"],
    ["credential", "Hardcoded Secrets / Credentials"],
    ["deserial", "Insecure Deserialization"],
    ["weak crypto", "Weak Cryptography Usage"],
    ["dependency", "Dependency Vulnerability"],
    ["auth", "Authentication / Authorization Flaw"],
    ["authorization", "Authentication / Authorization Flaw"],
    ["session", "Session Security Misconfiguration"],
    ["misconfig", "Security Misconfiguration"],
    ["ssrf", "Server-Side Request Forgery (SSRF)"],
    ["eval(", "Unsafe Eval Usage"],
  ];
  for (const [token, label] of hints) {
    if (blob.includes(token)) {
      return label;
    }
  }
  return "Security Finding";
}

function groupByAlert(findings: VulnerabilityFinding[]): AlertGroup[] {
  const map = new Map<string, AlertGroup>();
  for (const finding of findings) {
    const title = normalizedFindingTitle(finding);
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

function collectExecutionEvidenceRows(
  toolchainStatus: Record<string, ToolchainStatusEntry>,
): ExecutionEvidenceRow[] {
  const rows: ExecutionEvidenceRow[] = [];
  for (const [toolName, status] of Object.entries(toolchainStatus || {})) {
    const execution = status?.execution;
    const executionStatus = String(execution?.status || "unknown");
    const evidence: ToolExecutionEvidence[] = Array.isArray(execution?.evidence) ? execution.evidence : [];
    for (const record of evidence) {
      const command = String(record?.command || "").trim();
      const exitCodeRaw = record?.exit_code === null || record?.exit_code === undefined ? null : Number(record?.exit_code);
      const effectiveStatus =
        exitCodeRaw === null
          ? executionStatus
          : exitCodeRaw === 0
            ? "success"
            : "failed";
      if (["skipped", "skipped_irrelevant", "unavailable", "no_runner", "unknown"].includes(effectiveStatus)) {
        continue;
      }
      rows.push({
        tool: toolName,
        status: effectiveStatus,
        timestamp: String(record?.timestamp || ""),
        command,
        exitCode: exitCodeRaw === null ? "N/A" : String(exitCodeRaw),
        durationMs: Number(record?.duration_ms || 0),
        stdoutHash: String(record?.stdout_sha256 || ""),
        stderrHash: String(record?.stderr_sha256 || ""),
        stdoutBytes: Number(record?.stdout_bytes || 0),
        stderrBytes: Number(record?.stderr_bytes || 0),
        stdoutPreview: String(record?.stdout_preview || ""),
        stderrPreview: String(record?.stderr_preview || ""),
      });
    }
  }

  return rows.sort((a, b) => {
    const toolDiff = a.tool.localeCompare(b.tool);
    if (toolDiff !== 0) {
      return toolDiff;
    }
    return b.durationMs - a.durationMs;
  });
}

function collectToolTimingRows(
  toolchainStatus: Record<string, ToolchainStatusEntry>,
  toolchainExecution: ToolchainExecutionSummary | null,
): ToolTimingRow[] {
  const fromSummary = Array.isArray(toolchainExecution?.timing_breakdown) ? toolchainExecution.timing_breakdown : [];
  if (fromSummary.length > 0) {
    return fromSummary
      .map((item) => ({
        tool: String(item.tool || "unknown"),
        status: String(item.status || "unknown"),
        attempted: Boolean(item.attempted),
        durationMs: Number(item.duration_ms || 0),
        findingsCount: Number(item.findings_count || 0),
        errorsCount: Number(item.errors_count || 0),
        avgMsPerFinding:
          item.avg_ms_per_finding === null || item.avg_ms_per_finding === undefined
            ? null
            : Number(item.avg_ms_per_finding || 0),
      }))
      .sort((a, b) => b.durationMs - a.durationMs);
  }

  const rows: ToolTimingRow[] = [];
  for (const [toolName, status] of Object.entries(toolchainStatus || {})) {
    const execution = status?.execution;
    rows.push({
      tool: toolName,
      status: String(execution?.status || "unknown"),
      attempted: Boolean(execution?.attempted),
      durationMs: Number(execution?.duration_ms || 0),
      findingsCount: Number(execution?.findings_count || 0),
      errorsCount: Array.isArray(execution?.errors) ? execution.errors.length : 0,
      avgMsPerFinding:
        Number(execution?.findings_count || 0) > 0
          ? Number((Number(execution?.duration_ms || 0) / Number(execution?.findings_count || 1)).toFixed(2))
          : null,
    });
  }
  return rows.sort((a, b) => b.durationMs - a.durationMs);
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

function truncateForReport(value: unknown, maxChars = 1800): string {
  const text = String(value || "").trim();
  if (text.length <= maxChars) {
    return text;
  }
  return `${text.slice(0, maxChars)}\n... [truncated for report readability]`;
}

function cweNumber(value: string): string | null {
  const match = String(value || "").toUpperCase().match(/CWE-(\d+)/);
  return match ? match[1] : null;
}

function cweUrl(value: string): string | null {
  const id = cweNumber(value);
  if (!id) {
    return null;
  }
  return `https://cwe.mitre.org/data/definitions/${id}.html`;
}

function cveValues(input: unknown): string[] {
  if (Array.isArray(input)) {
    return input
      .map((value) => String(value || "").toUpperCase().trim())
      .filter((value) => /^CVE-\d{4}-\d{4,7}$/.test(value));
  }
  const text = String(input || "").toUpperCase();
  const matches = text.match(/CVE-\d{4}-\d{4,7}/g);
  return matches ? Array.from(new Set(matches)) : [];
}

function cveUrl(cve: string): string {
  return `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cve)}`;
}

function renderCweLink(value: string): string {
  const label = String(value || "N/A");
  const url = cweUrl(label);
  if (!url) {
    return escapeHtml(label);
  }
  return `<a href="${escapeHtml(url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(label)}</a>`;
}

function renderCveLinks(value: unknown): string {
  const ids = cveValues(value);
  if (!ids.length) {
    return "N/A";
  }
  return ids
    .slice(0, 12)
    .map((id) => `<a href="${escapeHtml(cveUrl(id))}" target="_blank" rel="noopener noreferrer">${escapeHtml(id)}</a>`)
    .join(", ");
}

function advisoryValues(finding: Pick<VulnerabilityFinding, "advisory_ids" | "cve_ids" | "dependency_id">): string[] {
  const values = new Set<string>();
  for (const value of finding.advisory_ids || []) {
    const text = String(value || "").trim().toUpperCase();
    if (text) {
      values.add(text);
    }
  }
  for (const value of finding.cve_ids || []) {
    const text = String(value || "").trim().toUpperCase();
    if (text) {
      values.add(text);
    }
  }
  const dependencyId = String(finding.dependency_id || "").trim().toUpperCase();
  if (dependencyId) {
    values.add(dependencyId);
  }
  return Array.from(values);
}

function advisoryUrl(id: string): string | null {
  const normalized = String(id || "").trim().toUpperCase();
  if (normalized.startsWith("CVE-")) {
    return cveUrl(normalized);
  }
  if (normalized.startsWith("GHSA-")) {
    return `https://github.com/advisories/${encodeURIComponent(normalized)}`;
  }
  return null;
}

function renderAdvisoryLinks(finding: Pick<VulnerabilityFinding, "advisory_ids" | "cve_ids" | "dependency_id">): string {
  const ids = advisoryValues(finding);
  if (!ids.length) {
    return "N/A";
  }
  return ids
    .slice(0, 12)
    .map((id) => {
      const url = advisoryUrl(id);
      if (!url) {
        return escapeHtml(id);
      }
      return `<a href="${escapeHtml(url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(id)}</a>`;
    })
    .join(", ");
}

function renderCvssLink(score: number | undefined): string {
  const safe = Number.isFinite(Number(score)) ? Number(score) : 0;
  const calculator = "https://www.first.org/cvss/calculator/3.1";
  return `<a href="${calculator}" target="_blank" rel="noopener noreferrer">${safe.toFixed(1)}</a>`;
}

function activePocStatusText(
  activePoc:
    | {
        status?: string;
        verification_basis?: string;
        confidence?: number | null;
      }
    | undefined,
): string {
  if (!activePoc) {
    return "Not executed for this finding in this scan.";
  }
  const status = String(activePoc.status || "not_executed");
  const basis = String(activePoc.verification_basis || "").trim();
  const confidence =
    activePoc.confidence !== null && activePoc.confidence !== undefined && Number.isFinite(Number(activePoc.confidence))
      ? `${(Number(activePoc.confidence) * 100).toFixed(0)}%`
      : "";
  const extras = [basis && basis !== "unknown" ? `basis=${basis}` : "", confidence ? `confidence=${confidence}` : ""].filter(Boolean);
  return extras.length ? `${status} (${extras.join(" | ")})` : status;
}

function activePocCommandText(activePoc: { command?: string } | undefined): string {
  const command = String(activePoc?.command || "").trim();
  return command || "No active PoC command was executed for this finding in this scan.";
}

function activePocOutputText(activePoc: { output?: string } | undefined): string {
  const output = String(activePoc?.output || "").trim();
  return output || "No active PoC output was captured for this finding in this scan.";
}

function normalizedFixVerificationSummary(
  summary:
    | {
        performed?: number;
        verified_fixed?: number;
        verification_failed?: number;
        inconclusive?: number;
        not_applicable?: number;
        skipped?: number;
        build_verified?: number;
        build_failed?: number;
        test_verified?: number;
        test_failed?: number;
      }
    | null
    | undefined,
  findings: VulnerabilityFinding[] = [],
): {
  performed: number;
  verified_fixed: number;
  verification_failed: number;
  inconclusive: number;
  not_applicable: number;
  skipped: number;
  build_verified: number;
  build_failed: number;
  test_verified: number;
  test_failed: number;
} {
  const normalized = {
    performed: Number(summary?.performed || 0),
    verified_fixed: Number(summary?.verified_fixed || 0),
    verification_failed: Number(summary?.verification_failed || 0),
    inconclusive: Number(summary?.inconclusive || 0),
    not_applicable: Number(summary?.not_applicable || 0),
    skipped: Number(summary?.skipped || 0),
    build_verified: Number(summary?.build_verified || 0),
    build_failed: Number(summary?.build_failed || 0),
    test_verified: Number(summary?.test_verified || 0),
    test_failed: Number(summary?.test_failed || 0),
  };
  const anySummaryValue = Object.values(normalized).some((value) => Number(value || 0) > 0);
  if (anySummaryValue || !Array.isArray(findings) || findings.length === 0) {
    return normalized;
  }

  const rebuilt = {
    performed: 0,
    verified_fixed: 0,
    verification_failed: 0,
    inconclusive: 0,
    not_applicable: 0,
    skipped: 0,
    build_verified: 0,
    build_failed: 0,
    test_verified: 0,
    test_failed: 0,
  };
  for (const finding of findings) {
    const verification = finding.fix_verification;
    if (!verification || typeof verification !== "object") {
      continue;
    }
    if (Boolean(verification.performed)) {
      rebuilt.performed += 1;
    }
    const result = String(verification.result || "").toLowerCase();
    if (result === "verified_fixed") {
      rebuilt.verified_fixed += 1;
    } else if (result === "verification_failed") {
      rebuilt.verification_failed += 1;
    } else if (result === "not_applicable") {
      rebuilt.not_applicable += 1;
    } else if (result === "skipped") {
      rebuilt.skipped += 1;
    } else if (result) {
      rebuilt.inconclusive += 1;
    }
    const buildVerification = verification.build_verification;
    if (String(buildVerification?.status || "").toLowerCase() === "success") {
      rebuilt.build_verified += 1;
    } else if (buildVerification) {
      rebuilt.build_failed += 1;
    }
    const testVerification = verification.test_verification;
    if (String(testVerification?.status || "").toLowerCase() === "success") {
      rebuilt.test_verified += 1;
    } else if (testVerification) {
      rebuilt.test_failed += 1;
    }
  }
  return rebuilt;
}

function fixVerificationResultText(
  verification:
    | {
        result?: string;
      }
    | undefined,
): string {
  const result = String(verification?.result || "").trim();
  return result || "Not executed";
}

function fixVerificationReasonText(
  verification:
    | {
        reason?: string;
      }
    | undefined,
): string {
  const reason = String(verification?.reason || "").trim();
  return reason || "No post-fix verification was performed for this finding in this scan.";
}

function hasReplaySummaryData(
  replay:
    | {
        findings_with_replay?: number;
        tool_evidence_records?: number;
        tools_with_evidence?: string[];
      }
    | null
    | undefined,
): boolean {
  if (!replay) {
    return false;
  }
  if (Number(replay.findings_with_replay || 0) > 0) {
    return true;
  }
  if (Number(replay.tool_evidence_records || 0) > 0) {
    return true;
  }
  return Array.isArray(replay.tools_with_evidence) && replay.tools_with_evidence.length > 0;
}

function hasIntegrityChainData(
  chain:
    | {
        report_sha256?: string;
        findings_sha256?: string;
        metadata_sha256?: string;
        tool_evidence_sha256?: string;
      }
    | null
    | undefined,
): boolean {
  if (!chain) {
    return false;
  }
  return Boolean(
    String(chain.report_sha256 || "").trim() ||
      String(chain.findings_sha256 || "").trim() ||
      String(chain.metadata_sha256 || "").trim() ||
      String(chain.tool_evidence_sha256 || "").trim(),
  );
}

function hasRiskIntelligenceData(
  riskIntel:
    | {
        findings_with_cve?: number;
        findings_cvss_ge_7?: number;
        known_exploited_findings?: number;
      }
    | null
    | undefined,
  releaseGateDistribution: Record<string, number> | null | undefined,
): boolean {
  if (riskIntel) {
    if (
      Number(riskIntel.findings_with_cve || 0) > 0 ||
      Number(riskIntel.findings_cvss_ge_7 || 0) > 0 ||
      Number(riskIntel.known_exploited_findings || 0) > 0
    ) {
      return true;
    }
  }
  if (!releaseGateDistribution) {
    return false;
  }
  return Object.values(releaseGateDistribution).some((value) => Number(value || 0) > 0);
}

function hasFalsePositiveCandidates(falsePositiveReport: unknown): boolean {
  if (!falsePositiveReport || typeof falsePositiveReport !== "object") {
    return false;
  }
  const candidateSource = (falsePositiveReport as { candidates?: unknown }).candidates;
  const candidates = Array.isArray(candidateSource)
    ? (candidateSource as Array<unknown>)
    : [];
  return candidates.length > 0;
}

function deriveRiskIntelligenceFromFindings(findings: VulnerabilityFinding[]): {
  findings_with_cve: number;
  findings_cvss_ge_7: number;
  known_exploited_findings: number;
} {
  let findingsWithCve = 0;
  let findingsCvssGe7 = 0;
  let knownExploitedFindings = 0;
  for (const finding of findings) {
    if (advisoryValues(finding).length > 0) {
      findingsWithCve += 1;
    }
    if (Number(finding.cvss_score || 0) >= 7) {
      findingsCvssGe7 += 1;
    }
    if (Boolean((finding as VulnerabilityFinding & { known_exploited?: boolean }).known_exploited)) {
      knownExploitedFindings += 1;
    }
  }
  return {
    findings_with_cve: findingsWithCve,
    findings_cvss_ge_7: findingsCvssGe7,
    known_exploited_findings: knownExploitedFindings,
  };
}

function deriveReleaseGateDistribution(findings: VulnerabilityFinding[]): Record<string, number> {
  const counters: Record<string, number> = {};
  for (const finding of findings) {
    const gate = Number(finding.cvss_score || 0) >= 9
      ? "Block release"
      : finding.severity === "High"
        ? "Fix before prod"
        : finding.severity === "Medium"
          ? "Scheduled fix"
          : "Track";
    counters[gate] = Number(counters[gate] || 0) + 1;
  }
  return counters;
}

function deriveAuthAbuseFromFindings(findings: VulnerabilityFinding[]):
  | {
      total_findings: number;
      severity_distribution: Record<string, number>;
      top_vulnerability_types: Array<{ type: string; count: number }>;
      affected_modules: Array<{ module: string; count: number; critical: number; high: number }>;
      affected_files: Array<{ file: string; folder: string; count: number; critical: number; high: number }>;
      issue_file_mapping: Array<{ issue_type: string; file: string; folder: string; count: number; critical: number; high: number }>;
    }
  | null {
  const scoped = findings.filter((finding) => {
    const combined = [
      normalizedFindingTitle(finding),
      String(finding.owasp_mapping || ""),
      String(finding.description || ""),
    ]
      .join(" ")
      .toLowerCase();
    return [
      "auth",
      "authorization",
      "broken access",
      "bola",
      "bopla",
      "permission",
      "privilege",
      "session",
      "cookie",
      "token",
      "brute force",
      "user enumeration",
      "credential",
      "account takeover",
    ].some((token) => combined.includes(token));
  });
  if (!scoped.length) {
    return null;
  }
  const severityDistribution: Record<string, number> = {};
  const typeCounts = new Map<string, number>();
  const fileCounts = new Map<string, { file: string; folder: string; count: number; critical: number; high: number }>();
  const moduleCounts = new Map<string, { module: string; count: number; critical: number; high: number }>();
  const mappingCounts = new Map<string, { issue_type: string; file: string; folder: string; count: number; critical: number; high: number }>();
  for (const finding of scoped) {
    severityDistribution[finding.severity] = Number(severityDistribution[finding.severity] || 0) + 1;
    const title = normalizedFindingTitle(finding);
    typeCounts.set(title, Number(typeCounts.get(title) || 0) + 1);
    const file = normalizePath(finding.file_path);
    const folder = folderFromPath(finding.file_path);
    const fileKey = `${file}@@${folder}`;
    const fileRow = fileCounts.get(fileKey) || { file, folder, count: 0, critical: 0, high: 0 };
    fileRow.count += 1;
    if (finding.severity === "Critical") fileRow.critical += 1;
    if (finding.severity === "High") fileRow.high += 1;
    fileCounts.set(fileKey, fileRow);
    const module = moduleFromFinding(finding);
    const moduleRow = moduleCounts.get(module) || { module, count: 0, critical: 0, high: 0 };
    moduleRow.count += 1;
    if (finding.severity === "Critical") moduleRow.critical += 1;
    if (finding.severity === "High") moduleRow.high += 1;
    moduleCounts.set(module, moduleRow);
    const mapKey = `${title}@@${file}@@${folder}`;
    const mappingRow = mappingCounts.get(mapKey) || { issue_type: title, file, folder, count: 0, critical: 0, high: 0 };
    mappingRow.count += 1;
    if (finding.severity === "Critical") mappingRow.critical += 1;
    if (finding.severity === "High") mappingRow.high += 1;
    mappingCounts.set(mapKey, mappingRow);
  }
  return {
    total_findings: scoped.length,
    severity_distribution: severityDistribution,
    top_vulnerability_types: Array.from(typeCounts.entries())
      .map(([type, count]) => ({ type, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 10),
    affected_modules: Array.from(moduleCounts.values()).sort((a, b) => b.count - a.count).slice(0, 15),
    affected_files: Array.from(fileCounts.values()).sort((a, b) => b.count - a.count).slice(0, 20),
    issue_file_mapping: Array.from(mappingCounts.values()).sort((a, b) => b.count - a.count).slice(0, 30),
  };
}

function hasMeaningfulAuthAbuse(
  authAbuse:
    | {
        total_findings?: number;
        top_vulnerability_types?: Array<{ type: string; count: number }>;
        affected_files?: Array<{ file: string; count: number; critical: number; high: number }>;
        issue_file_mapping?: Array<{ issue_type: string; file: string; folder: string; count: number; critical: number; high: number }>;
      }
    | null
    | undefined,
): boolean {
  if (!authAbuse) {
    return false;
  }
  return (
    Number(authAbuse.total_findings || 0) > 0 ||
    Boolean(authAbuse.top_vulnerability_types?.length) ||
    Boolean(authAbuse.affected_files?.length) ||
    Boolean(authAbuse.issue_file_mapping?.length)
  );
}

function severityPriorityWeight(severity: string): number {
  switch (severity) {
    case "Critical":
      return 96;
    case "High":
      return 78;
    case "Medium":
      return 56;
    case "Low":
      return 34;
    default:
      return 16;
  }
}

function deriveReleaseGateForFinding(finding: VulnerabilityFinding): string {
  if (finding.release_gate_action) {
    return String(finding.release_gate_action);
  }
  if (finding.severity === "Critical" || Number(finding.cvss_score || 0) >= 9) {
    return "Block release";
  }
  if (finding.severity === "High") {
    return "Fix before prod";
  }
  if (finding.severity === "Medium") {
    return "Scheduled fix";
  }
  return "Track";
}

function deriveSlaHoursForFinding(finding: VulnerabilityFinding): number {
  switch (finding.severity) {
    case "Critical":
      return 24;
    case "High":
      return 72;
    case "Medium":
      return 168;
    case "Low":
      return 336;
    default:
      return 720;
  }
}

function deriveExploitabilityScore(finding: VulnerabilityFinding): number {
  const cvssScore = Number(finding.cvss_score || 0);
  const validated = String(finding.active_poc?.status || "").toLowerCase() === "verified";
  const knownExploited = Boolean((finding as VulnerabilityFinding & { known_exploited?: boolean }).known_exploited);
  const score = Math.min(
    1,
    (cvssScore / 10) * 0.58 +
      severityPriorityWeight(finding.severity) / 180 +
      (validated ? 0.22 : 0) +
      (knownExploited ? 0.14 : 0),
  );
  return Math.max(0.05, Math.round(score * 100) / 100);
}

function deriveBusinessImpactScore(finding: VulnerabilityFinding): number {
  const explicit = String(finding.business_impact || "").toLowerCase();
  if (explicit.includes("critical") || explicit.includes("production outage")) {
    return 0.95;
  }
  if (explicit.includes("high") || explicit.includes("service disruption") || explicit.includes("credential")) {
    return 0.82;
  }
  if (explicit.includes("medium") || explicit.includes("degrade")) {
    return 0.64;
  }
  return Math.max(0.2, Math.round((severityPriorityWeight(finding.severity) / 100) * 100) / 100);
}

function rankedFindings(findings: VulnerabilityFinding[], limit = findings.length): VulnerabilityFinding[] {
  return [...findings]
    .sort((left, right) => {
      const leftPriority = Number((left as VulnerabilityFinding & { risk_priority_score?: number }).risk_priority_score || 0);
      const rightPriority = Number((right as VulnerabilityFinding & { risk_priority_score?: number }).risk_priority_score || 0);
      const leftScore = leftPriority || Number(left.cvss_score || 0) + severityPriorityWeight(left.severity) / 100;
      const rightScore = rightPriority || Number(right.cvss_score || 0) + severityPriorityWeight(right.severity) / 100;
      if (rightScore !== leftScore) {
        return rightScore - leftScore;
      }
      return SEVERITY_ORDER.indexOf(left.severity) - SEVERITY_ORDER.indexOf(right.severity);
    })
    .slice(0, limit);
}

function resolveRiskIntelligence(
  summary: VulnerabilityFixedCodeReport["summary"] & {
    risk_intelligence?: { findings_with_cve?: number; findings_cvss_ge_7?: number; known_exploited_findings?: number };
  },
  findings: VulnerabilityFinding[],
): { findings_with_cve: number; findings_cvss_ge_7: number; known_exploited_findings: number } {
  const existing = summary.risk_intelligence;
  if (existing) {
    return {
      findings_with_cve: Number(existing.findings_with_cve || 0),
      findings_cvss_ge_7: Number(existing.findings_cvss_ge_7 || 0),
      known_exploited_findings: Number(existing.known_exploited_findings || 0),
    };
  }
  return deriveRiskIntelligenceFromFindings(findings);
}

function resolveAuthAbuse(
  summary: VulnerabilityFixedCodeReport["summary"] & {
    auth_abuse_session_security?: {
      total_findings?: number;
      severity_distribution?: Record<string, number>;
      top_vulnerability_types?: Array<{ type: string; count: number }>;
      affected_modules?: Array<{ module: string; count: number; critical: number; high: number }>;
      affected_files?: Array<{ file: string; folder: string; count: number; critical: number; high: number }>;
      issue_file_mapping?: Array<{ issue_type: string; file: string; folder: string; count: number; critical: number; high: number }>;
    };
  },
  findings: VulnerabilityFinding[],
): ReturnType<typeof deriveAuthAbuseFromFindings> {
  const existing = summary.auth_abuse_session_security || null;
  if (hasMeaningfulAuthAbuse(existing)) {
    return {
      total_findings: Number(existing?.total_findings || 0),
      severity_distribution: existing?.severity_distribution || {},
      top_vulnerability_types: existing?.top_vulnerability_types || [],
      affected_modules: existing?.affected_modules || [],
      affected_files: existing?.affected_files || [],
      issue_file_mapping: existing?.issue_file_mapping || [],
    };
  }
  return deriveAuthAbuseFromFindings(findings);
}

function resolveCtoBoardView(
  roleAware: Record<string, unknown>,
  findings: VulnerabilityFinding[],
  summary: VulnerabilityFixedCodeReport["summary"],
  riskIntel: { findings_with_cve: number; findings_cvss_ge_7: number; known_exploited_findings: number },
): Record<string, unknown> {
  const existing = (roleAware.cto_board_view as Record<string, unknown>) || {};
  const urgent = Array.isArray(existing.top_5_urgent_risks) ? existing.top_5_urgent_risks : [];
  const aiSummary = Array.isArray(existing.ai_summary_plain_language) ? existing.ai_summary_plain_language : [];
  if (Object.keys(existing).length > 0 && (urgent.length > 0 || aiSummary.length > 0 || existing.financial_exposure_usd || existing.downtime_estimate)) {
    return existing;
  }
  const ranked = rankedFindings(findings, 5);
  const totalFindings = findings.length;
  const activeRisk = Number(summary.active_risk_findings || 0);
  const likelyLoss = Math.round(activeRisk * 185000 + riskIntel.known_exploited_findings * 95000 + totalFindings * 4200);
  const likelyDowntime = Math.round((activeRisk * 4.5 + riskIntel.findings_cvss_ge_7 * 0.7) * 10) / 10;
  return {
    business_risk_exposure_score: Number(summary.risk_score || 0),
    trend: { available: false, direction: "stable", delta_points: 0 },
    financial_exposure_usd: {
      best_case_usd: Math.round(likelyLoss * 0.55),
      most_likely_usd: likelyLoss,
      worst_case_usd: Math.round(likelyLoss * 1.7),
    },
    downtime_estimate: {
      best_case_hours: Math.round(likelyDowntime * 0.6 * 10) / 10,
      most_likely_hours: likelyDowntime,
      worst_case_hours: Math.round(likelyDowntime * 1.8 * 10) / 10,
    },
    top_5_urgent_risks: ranked.map((finding) => ({
      title: normalizedFindingTitle(finding),
      severity: finding.severity,
      priority_score: Number((finding as VulnerabilityFinding & { risk_priority_score?: number }).risk_priority_score || finding.cvss_score || 0),
      business_impact: finding.business_impact || "Material engineering and service risk.",
    })),
    ai_summary_plain_language: [
      `${activeRisk} high-priority finding(s) are still open across ${Number(summary.files_impacted || 0)} impacted file(s).`,
      `${riskIntel.findings_with_cve} finding(s) carry advisory identifiers and ${riskIntel.known_exploited_findings} map to known exploited intelligence.`,
      `Release pressure remains ${activeRisk > 0 ? "elevated" : "controlled"} based on current critical/high finding volume and analyzer coverage.`,
    ],
  };
}

function resolveCisoSecurityView(
  roleAware: Record<string, unknown>,
  findings: VulnerabilityFinding[],
): Record<string, unknown> {
  const existing = (roleAware.ciso_security_view as Record<string, unknown>) || {};
  const table = Array.isArray(existing.vulnerability_operational_table)
    ? (existing.vulnerability_operational_table as Array<Record<string, unknown>>)
    : [];
  if (table.length > 0) {
    return existing;
  }
  return {
    attack_chain_example: "External attacker -> service/API -> lateral movement -> critical asset impact",
    vulnerability_operational_table: rankedFindings(findings, 20).map((finding) => ({
      title: normalizedFindingTitle(finding),
      severity: finding.severity,
      cvss_score: Number(finding.cvss_score || 0),
      exploitability_score: deriveExploitabilityScore(finding),
      business_impact_score: deriveBusinessImpactScore(finding),
      priority_score: Number((finding as VulnerabilityFinding & { risk_priority_score?: number }).risk_priority_score || finding.cvss_score || 0),
      active_exploit_flag: Boolean((finding as VulnerabilityFinding & { known_exploited?: boolean }).known_exploited),
      release_gate_action: deriveReleaseGateForFinding(finding),
      sla_hours: deriveSlaHoursForFinding(finding),
    })),
  };
}

function resolveDeveloperDevopsView(
  roleAware: Record<string, unknown>,
  findings: VulnerabilityFinding[],
): Record<string, unknown> {
  const existing = (roleAware.developer_devops_view as Record<string, unknown>) || {};
  const rows = Array.isArray(existing.tactical_findings) ? existing.tactical_findings : [];
  if (rows.length > 0) {
    return existing;
  }
  return {
    tactical_findings: rankedFindings(findings, 24).map((finding) => ({
      title: normalizedFindingTitle(finding),
      severity: finding.severity,
      file_path: normalizePath(finding.file_path),
      line_number: Number(finding.line_number || 1),
      cwe_id: finding.cwe_id || "N/A",
      owasp_mapping: finding.owasp_mapping || "N/A",
      secure_fix_snippet: preferredFindingFix(finding),
    })),
  };
}

function resolveRiskStoryMode(
  roleAware: Record<string, unknown>,
  findings: VulnerabilityFinding[],
): Record<string, unknown> {
  const existing = (roleAware.risk_story_mode as Record<string, unknown>) || {};
  if (Object.keys(existing).length > 0 && (existing.scenario_title || existing.narrative || existing.likely_outcome)) {
    return existing;
  }
  const topFindings = rankedFindings(findings, 3);
  if (!topFindings.length) {
    return {};
  }
  const titles = topFindings.map((finding) => normalizedFindingTitle(finding));
  return {
    scenario_title: "Code-path exploitation chain",
    narrative: `An attacker who reaches ${titles.join(", ")} can chain exposed code paths into broader service or credential impact if the findings stay unremediated.`,
    likely_outcome: {
      likely_path: titles.join(" -> "),
      most_affected_area: normalizePath(topFindings[0].file_path),
      primary_release_gate: deriveReleaseGateForFinding(topFindings[0]),
    },
  };
}

function summaryValueOrZero(value: unknown): number {
  const numeric = Number(value);
  return Number.isFinite(numeric) ? numeric : 0;
}

function resolveAdvancedFeatures(
  roleAware: Record<string, unknown>,
  findings: VulnerabilityFinding[],
  enterprise: EnterpriseAssuranceSummary | null,
  dataQuality: DataQualitySummary,
): Record<string, unknown> {
  const existing = (roleAware.advanced_features as Record<string, unknown>) || {};
  const fixPlan = Object.keys((existing.what_should_i_fix_first_ai as Record<string, unknown>) || {}).length > 0
    ? (existing.what_should_i_fix_first_ai as Record<string, unknown>)
    : buildFallbackFixWindowPlan(findings);
  const aiSolutionEngine = (existing.ai_solution_engine as Record<string, unknown>) || {};
  return {
    ...existing,
    security_maturity_scoring:
      (existing.security_maturity_scoring as Record<string, unknown>) || {
        overall_score: summaryValueOrZero(dataQuality.coverage_confidence_score),
        patch_speed_score: Number(enterprise?.toolchain_success_rate_percent || 0),
        exposure_window_score: Math.max(0, 100 - Number(enterprise?.readiness_score || 0)),
        developer_fix_velocity_score: Math.max(0, 100 - Number(dataQuality.dedup_ratio_percent || 0)),
      },
    ai_solution_engine: Object.keys(aiSolutionEngine).length > 0
      ? aiSolutionEngine
      : {
          description: "Evidence-driven local remediation engine using finding context, code location, and validation evidence.",
          mode: "context-aware",
          provider: "local-evidence-driven",
          model: "parser-flow-validation-v2",
          status: "ready",
          grounded_generation: true,
          prioritization_status: "ready",
        },
    what_should_i_fix_first_ai: fixPlan,
  };
}

function preferredFindingFix(finding: VulnerabilityFinding): string {
  const aiFix = String(finding.ai_suggested_fix || "").trim();
  if (aiFix) {
    return aiFix;
  }
  const fixedCode = String(finding.fixed_code || "").trim();
  if (fixedCode) {
    return fixedCode;
  }
  const recommendation = String(finding.recommendation || "").trim();
  if (recommendation) {
    return recommendation;
  }
  return "No direct fix available.";
}

function fixArtifactKind(finding: VulnerabilityFinding): "exact_patch" | "guidance" {
  if (finding.fix_artifact_kind === "exact_patch" || finding.fix_artifact_kind === "guidance") {
    return finding.fix_artifact_kind;
  }
  const fixedCode = String(finding.fixed_code || "").trim();
  const confidence = String(finding.remediation_confidence || "").trim().toLowerCase();
  if (fixedCode && !fixedCode.startsWith("#") && (confidence === "high" || confidence === "medium")) {
    return "exact_patch";
  }
  return "guidance";
}

function fixArtifactLabel(finding: VulnerabilityFinding): string {
  const label = String(finding.fix_artifact_label || "").trim();
  if (label) {
    return label;
  }
  return fixArtifactKind(finding) === "exact_patch" ? "Suggested Fix" : "Remediation Guidance";
}

function aiFixConfidenceLabel(value: { ai_fix_confidence_label?: string; remediation_confidence?: string }): string {
  const label = String(value.ai_fix_confidence_label || value.remediation_confidence || "").trim();
  if (label) {
    return label;
  }
  return "Medium";
}

function aiFixConfidenceScore(value: { ai_fix_confidence_score?: number; remediation_confidence?: string }): number {
  const explicit = Number(value.ai_fix_confidence_score ?? Number.NaN);
  if (Number.isFinite(explicit) && explicit >= 0) {
    return Math.max(0, Math.min(1, explicit));
  }
  const confidence = aiFixConfidenceLabel(value).toLowerCase();
  if (confidence === "high") {
    return 0.85;
  }
  if (confidence === "low") {
    return 0.35;
  }
  return 0.6;
}

function aiGroundingStatus(value: { ai_fix_grounded?: boolean }): string {
  return value.ai_fix_grounded === false ? "No" : "Yes";
}

function aiGroundingNotes(value: { ai_grounding_notes?: string }): string {
  return String(value.ai_grounding_notes || "").trim() || "Grounded on the finding evidence, code context, and safe validation data available in this scan.";
}

function dependencyAuthenticitySummary(
  finding: {
    dependency_reachability?: {
      status?: string;
      manifest_present?: boolean;
      lockfile_present?: boolean;
      manifest_paths?: string[];
      lockfile_paths?: string[];
      import_evidence?: string[];
      declared_versions?: string[];
      locked_versions?: string[];
      advisory_ids?: string[];
      advisory_verified?: boolean;
      reasoning?: string;
    };
  },
): string {
  const reachability = finding.dependency_reachability;
  if (!reachability) {
    return "";
  }
  const parts = [
    `status=${String(reachability.status || "unknown")}`,
    `manifest=${reachability.manifest_present ? "yes" : "no"}`,
    `lockfile=${reachability.lockfile_present ? "yes" : "no"}`,
    `advisory_verified=${reachability.advisory_verified === false ? "no" : "yes"}`,
  ];
  const declared = (reachability.declared_versions || []).slice(0, 2).join(", ");
  const locked = (reachability.locked_versions || []).slice(0, 2).join(", ");
  const imports = (reachability.import_evidence || []).slice(0, 2).join(", ");
  if (declared) {
    parts.push(`declared=${declared}`);
  }
  if (locked) {
    parts.push(`locked=${locked}`);
  }
  if (imports) {
    parts.push(`imports=${imports}`);
  }
  return parts.join(" | ");
}

function dependencyAuthenticityDetail(
  finding: {
    dependency_reachability?: {
      manifest_paths?: string[];
      lockfile_paths?: string[];
      advisory_ids?: string[];
      reasoning?: string;
    };
  },
): string {
  const reachability = finding.dependency_reachability;
  if (!reachability) {
    return "";
  }
  const notes = [
    (reachability.manifest_paths || []).length ? `Manifest paths: ${(reachability.manifest_paths || []).slice(0, 3).join(", ")}` : "",
    (reachability.lockfile_paths || []).length ? `Lockfile paths: ${(reachability.lockfile_paths || []).slice(0, 3).join(", ")}` : "",
    (reachability.advisory_ids || []).length ? `Advisories: ${(reachability.advisory_ids || []).slice(0, 4).join(", ")}` : "",
    String(reachability.reasoning || "").trim(),
  ].filter(Boolean);
  return notes.join(" | ");
}

function renderFixWindowValue(value: unknown, findingByUid?: Map<string, VulnerabilityFinding>): string {
  if (!Array.isArray(value) || value.length === 0) {
    return "<span class='muted'>No prioritized fixes for this window.</span>";
  }
  const entries = value as Array<Record<string, unknown> | string>;
  const rendered = entries
    .slice(0, 6)
    .map((entry) => {
      if (typeof entry === "string") {
        const finding = findingByUid?.get(entry);
        if (!finding) {
          return `<div class="ai-fix-item"><div><strong>${escapeHtml(entry)}</strong></div><div class="muted">Finding metadata unavailable in this report snapshot.</div></div>`;
        }
        const title = normalizedFindingTitle(finding);
        const normalizedTitle = title.trim().toLowerCase();
        const severity = finding.severity || "Info";
        const rawFilePath = String(finding.file_path || "").trim();
        if (!rawFilePath || ["", "issue", "unknown", "n/a", "unclassified security finding"].includes(normalizedTitle)) {
          return "";
        }
        const location = `${normalizePath(rawFilePath)}:${Number(finding.line_number || 1)}`;
        const recommendedFix = preferredFindingFix(finding);
        const confidenceLabel = aiFixConfidenceLabel(finding);
        const confidenceScore = aiFixConfidenceScore(finding);
        const detailParts = [
          "Prioritized from the current finding set.",
          recommendedFix ? `Fix: ${recommendedFix}` : "",
          `Fix confidence: ${confidenceLabel} (${confidenceScore.toFixed(2)})`,
        ].filter(Boolean);
        return `<div class="ai-fix-item">
        <div><strong>${escapeHtml(title)}</strong> <span class="sev sev-${escapeHtml(severity)}">${escapeHtml(severity)}</span></div>
        <div class="muted">${escapeHtml(location)}</div>
        <div>${escapeHtml(detailParts.join(" | "))}</div>
      </div>`;
      }
      const entryUid = String(entry.finding_uid || "");
      const fallbackFinding = entryUid && findingByUid ? findingByUid.get(entryUid) : undefined;
      const title = String(
        entry.title || (fallbackFinding ? normalizedFindingTitle(fallbackFinding) : entry.finding_uid) || "Issue",
      );
      const normalizedTitle = title.trim().toLowerCase();
      const severity = String(entry.severity || fallbackFinding?.severity || "Info");
      const rawFilePath = String(entry.file_path || fallbackFinding?.file_path || "").trim();
      const lineNumber = Number(entry.line_number || fallbackFinding?.line_number || 1);
      const whyFirst = String(entry.why_first || "");
      const recommendedFix = String(entry.recommended_fix || "");
      const validationCommand = String(entry.validation_command || "");
      const priorityScore = Number(entry.priority_score || 0);
      const confidenceLabel = String(entry.fix_confidence_label || aiFixConfidenceLabel(fallbackFinding || {})).trim() || "Medium";
      const confidenceScore = Number(entry.fix_confidence_score || aiFixConfidenceScore(fallbackFinding || {}));
      if (!rawFilePath || ["", "issue", "unknown", "n/a", "unclassified security finding"].includes(normalizedTitle)) {
        return "";
      }
      if (priorityScore <= 0 && !["Critical", "High", "Medium"].includes(severity)) {
        return "";
      }
      const location = `${normalizePath(rawFilePath)}:${lineNumber}`;
      const detailParts = [
        whyFirst,
        recommendedFix ? `Fix: ${recommendedFix}` : "",
        validationCommand ? `Validate: ${validationCommand}` : "",
        `Fix confidence: ${confidenceLabel} (${confidenceScore.toFixed(2)})`,
      ].filter(Boolean);
      return `<div class="ai-fix-item">
        <div><strong>${escapeHtml(title)}</strong> <span class="sev sev-${escapeHtml(severity)}">${escapeHtml(severity)}</span></div>
        <div class="muted">${escapeHtml(location)} | priority=${priorityScore.toFixed(2)}</div>
        <div>${escapeHtml(detailParts.join(" | "))}</div>
      </div>`;
    })
    .filter(Boolean)
    .join("");
  return rendered || "<span class='muted'>No prioritized fixes for this window.</span>";
}

function buildFallbackFixWindowPlan(findings: VulnerabilityFinding[]): Record<string, Array<Record<string, unknown>>> {
  const ranked = [...findings]
    .filter((finding) => {
      const title = normalizedFindingTitle(finding).trim().toLowerCase();
      return Boolean(String(finding.file_path || "").trim()) && !["", "issue", "unknown", "n/a", "unclassified security finding"].includes(title);
    })
    .sort((left, right) => {
      const leftPriority = Number((left as VulnerabilityFinding & { risk_priority_score?: number }).risk_priority_score || left.cvss_score || 0);
      const rightPriority = Number((right as VulnerabilityFinding & { risk_priority_score?: number }).risk_priority_score || right.cvss_score || 0);
      if (rightPriority !== leftPriority) {
        return rightPriority - leftPriority;
      }
      const leftSeverity = SEVERITY_ORDER.indexOf(left.severity || "Info");
      const rightSeverity = SEVERITY_ORDER.indexOf(right.severity || "Info");
      return leftSeverity - rightSeverity;
    });
  const windows: Record<string, number> = { "8_hours": 2, "24_hours": 6, "72_hours": 15 };
  const plan: Record<string, Array<Record<string, unknown>>> = {};
  for (const [window, limit] of Object.entries(windows)) {
    plan[window] = ranked.slice(0, limit).map((finding) => ({
      finding_uid: finding.finding_uid,
      title: normalizedFindingTitle(finding),
      severity: finding.severity || "Info",
      file_path: finding.file_path,
      line_number: finding.line_number || 1,
      priority_score: Number((finding as VulnerabilityFinding & { risk_priority_score?: number }).risk_priority_score || finding.cvss_score || 0),
      why_first: String(finding.ai_remediation_summary || finding.recommendation || "").trim(),
      recommended_fix: String(finding.ai_suggested_fix || finding.fixed_code || finding.recommendation || "").trim(),
      validation_command: String(finding.active_poc?.command || "").trim(),
      ai_provider: String(finding.ai_fix_source || "local-evidence-driven:evidence-rules-v1"),
      fix_confidence_label: aiFixConfidenceLabel(finding),
      fix_confidence_score: aiFixConfidenceScore(finding),
    }));
  }
  return plan;
}

function resolvedAiRemediationSummary(finding: VulnerabilityFinding): string {
  const value = String(finding.ai_remediation_summary || "").trim();
  if (value) {
    return value;
  }
  const location = `${normalizePath(finding.file_path)}:${Number(finding.line_number || 1)}`;
  const fixKind = fixArtifactKind(finding) === "exact_patch" ? "exact patch" : "guidance-driven fix";
  const recommendation = String(finding.recommendation || "").trim();
  const base = `${normalizedFindingTitle(finding)} at ${location} requires ${fixKind} remediation based on the captured code evidence.`;
  return recommendation ? `${base} ${recommendation}` : base;
}

function resolvedAiValidationSteps(finding: VulnerabilityFinding): string {
  const value = String(finding.ai_validation_steps || "").trim();
  if (value) {
    return value;
  }
  const command = String(finding.active_poc?.command || "").trim();
  const steps = [
    "1. Apply the recommended code change to the affected file and line shown in this report.",
    "2. Re-run the affected application flow or regression test and compare the result with the pre-fix baseline.",
    command
      ? `3. Re-run the recorded safe validation command: ${command}`
      : "3. Re-run the recorded safe validation steps for this finding after the change.",
    "4. Close the finding only if the unsafe behavior no longer reproduces.",
  ];
  return steps.join("\n");
}

function workflowStatusText(status: string | undefined): string {
  return status === "Reviewed" ? "Reviewed" : "Open";
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
    const normalized = value.trim().toLowerCase();
    if (!normalized || normalized === "undefined" || normalized === "null") {
      return "N/A";
    }
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

function renderComplianceMatrixRows(items: Array<{ standard: string; control_count: number; status: string }>): string {
  return items
    .map(
      (item) => `<tr>
        <td>${escapeHtml(String(item.standard || "N/A"))}</td>
        <td align="center">${Number(item.control_count || 0)}</td>
        <td>${escapeHtml(String(item.status || "partial"))}</td>
      </tr>`,
    )
    .join("");
}

function exportThemeCss(extra = ""): string {
  const globeTextureCss = REPORT_GLOBE_TEXTURE_DATA_URI
    ? `url("${REPORT_GLOBE_TEXTURE_DATA_URI}")`
    : "radial-gradient(circle at 35% 35%, rgba(164, 224, 255, 0.18), rgba(14, 33, 54, 0.88) 58%, rgba(2, 8, 14, 1) 100%)";
  return `
    :root{--bg:#06111d;--bg2:#0a1c31;--panel:#0d1d33;--panel2:#10253f;--line:#28486b;--line-soft:#1b3550;--text:#dce9f7;--muted:#94b0ca;--accent:#38c9ff;--critical:#ff5b77;--high:#ff9b4b;--medium:#ffd65e;--low:#67b8ff;--info:#70d5ab;--ok:#6de2b4}
    *{box-sizing:border-box}
    html,body{margin:0;padding:0}
    body{position:relative;overflow-x:hidden;font-family:"Segoe UI Variable Text","Segoe UI","Trebuchet MS",Tahoma,sans-serif;font-size:13.5px;line-height:1.58;letter-spacing:.01em;color:var(--text);background:
      radial-gradient(circle at 0% 0%, rgba(56,201,255,0.08), transparent 34%),
      radial-gradient(circle at 100% 0%, rgba(103,184,255,0.08), transparent 28%),
      linear-gradient(180deg,var(--bg2),var(--bg) 46%, #040b12 100%);padding:18px}
    body::before{content:"";position:fixed;right:-7vw;top:-4vh;width:min(58vw,840px);aspect-ratio:1;border-radius:50%;
      background-image:${globeTextureCss};background-repeat:repeat-x;background-size:auto 100%;background-position:36% 50%;
      box-shadow:inset -58px -30px 118px rgba(0,0,0,0.62),inset 22px 18px 30px rgba(92,209,255,0.06),0 28px 84px rgba(0,0,0,0.42);
      border:1px solid rgba(110,226,255,0.22);opacity:.44;filter:saturate(1.16) contrast(1.22) brightness(1.06);
      animation:reportGlobeSpin 88s linear infinite;pointer-events:none;z-index:0}
    body::after{content:"";position:fixed;right:-3vw;top:6vh;width:min(49vw,700px);aspect-ratio:1;border-radius:50%;
      background:radial-gradient(circle at 36% 34%, rgba(154,224,255,0.16), transparent 34%),radial-gradient(circle at center, rgba(14,31,52,0.2), transparent 68%);
      box-shadow:0 0 48px rgba(53,209,255,0.14), inset 0 0 22px rgba(105,214,255,0.08);opacity:.5;pointer-events:none;z-index:0}
    @keyframes reportGlobeSpin{from{background-position:36% 50%}to{background-position:-164% 50%}}
    h1,h2,h3,h4{margin:0;color:#f5fbff}
    h1{font-size:36px;line-height:1.04;letter-spacing:-.035em}
    h2{font-size:22px;line-height:1.14;letter-spacing:-.02em;margin-bottom:12px}
    h3{font-size:16px;line-height:1.22;letter-spacing:-.012em;margin-bottom:10px}
    h4{font-size:13px;line-height:1.35;letter-spacing:.01em;margin:0 0 8px}
    p{margin:0 0 10px}
    ul,ol{margin:0;padding-left:20px}
    .report-shell{max-width:1520px;margin:0 auto;position:relative;z-index:1}
    .hero,.section{background:linear-gradient(165deg,rgba(17,37,63,0.42),rgba(10,27,46,0.28));border:1px solid rgba(120,168,205,0.34);border-radius:18px;box-shadow:0 14px 34px rgba(0,0,0,0.1);padding:22px;margin-bottom:16px}
    .hero{padding:24px}
    .hero-meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:10px;margin-top:16px}
    .meta-pill{border:1px solid rgba(120,168,205,0.28);border-radius:999px;background:rgba(4,14,24,0.1);padding:10px 14px;color:var(--muted);font-size:12.5px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
    .hero-grid,.stat-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:12px;margin-top:16px}
    .stat-card{border:1px solid rgba(120,168,205,0.26);border-radius:16px;background:linear-gradient(180deg,rgba(6,17,29,0.22),rgba(8,21,36,0.18));padding:14px 16px;min-height:96px}
    .stat-card .label{display:block;color:var(--muted);font-size:10.5px;text-transform:uppercase;letter-spacing:.11em;margin-bottom:8px}
    .stat-card .value{display:block;font-size:30px;font-weight:700;line-height:1.06;letter-spacing:-.025em}
    .stat-card .sub{display:block;color:var(--muted);font-size:11px;margin-top:8px}
    .tone-critical .value{color:var(--critical)}
    .tone-high .value{color:var(--high)}
    .tone-medium .value{color:var(--medium)}
    .tone-low .value{color:var(--low)}
    .tone-info .value{color:var(--info)}
    .tone-accent .value{color:var(--accent)}
    .section-grid{display:grid;grid-template-columns:minmax(0,1.1fr) minmax(0,.9fr);gap:14px}
    .stack{display:grid;gap:14px}
    .table-frame{border:1px solid rgba(120,168,205,0.24);border-radius:16px;overflow:hidden;background:rgba(6,17,29,0.14)}
    .table-scroll{overflow:auto;max-width:100%}
    table{width:100%;border-collapse:collapse;table-layout:fixed;line-height:1.52}
    th,td{border:1px solid var(--line-soft);padding:10px 12px;vertical-align:top}
    th{background:rgba(16,37,63,0.32);color:#c6d9ec;text-align:left;font-size:12px;letter-spacing:.04em;text-transform:uppercase}
    .table-scroll thead th{position:sticky;top:0;z-index:1}
    td{background:rgba(8,21,36,0.14)}
    tr:nth-child(even) td{background:rgba(10,26,43,0.08)}
    th,td{word-break:break-word}
    .muted{color:var(--muted)}
    .meta{color:var(--muted);font-size:12.5px}
    .code,pre{margin:0;white-space:pre-wrap;word-break:break-word;font-family:Consolas,monospace;border:1px solid rgba(120,168,205,0.24);border-radius:14px;background:rgba(5,16,26,0.16);color:var(--text);padding:12px;font-size:12px;line-height:1.55}
    .code-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px}
    .callout{border-left:4px solid var(--accent);padding:12px 14px;border-radius:12px;background:rgba(6,17,29,0.14)}
    .sev{display:inline-flex;align-items:center;border-radius:999px;padding:3px 8px;font-size:11px;font-weight:700;border:1px solid var(--line-soft)}
    .sev-Critical,.sev-critical{background:rgba(255,91,119,0.12);color:#ffdbe3}
    .sev-High,.sev-high{background:rgba(255,155,75,0.12);color:#ffe3cc}
    .sev-Medium,.sev-medium{background:rgba(255,214,94,0.14);color:#fff5c8}
    .sev-Low,.sev-low{background:rgba(103,184,255,0.14);color:#ddecff}
    .sev-Info,.sev-info{background:rgba(112,213,171,0.14);color:#dffaf0}
    .table-note{margin-top:10px;color:var(--muted);font-size:12px;line-height:1.55}
    .kpi-bars{display:grid;gap:8px}
    .kpi-row{display:grid;grid-template-columns:minmax(180px,32%) 1fr auto;gap:12px;align-items:center}
    .kpi-label{color:var(--muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
    .kpi-track{height:12px;border:1px solid var(--line);border-radius:999px;background:#071424;overflow:hidden}
    .kpi-fill{height:100%;background:linear-gradient(90deg,#1f88ff,var(--accent));min-width:2px}
    .kpi-row.tone-critical .kpi-fill{background:linear-gradient(90deg,#7a1f36,var(--critical))}
    .kpi-row.tone-high .kpi-fill{background:linear-gradient(90deg,#6d3b15,var(--high))}
    .kpi-row.tone-medium .kpi-fill{background:linear-gradient(90deg,#6b5a0f,var(--medium))}
    .kpi-row.tone-low .kpi-fill{background:linear-gradient(90deg,#20598a,var(--low))}
    .kpi-row.tone-info .kpi-fill{background:linear-gradient(90deg,#1e5c4a,var(--info))}
    .kpi-value{font-weight:600}
    .section-divider{height:1px;border:0;background:linear-gradient(90deg,var(--line),transparent);margin:10px 0}
    .avoid-break{break-inside:avoid-page;page-break-inside:avoid}
    a{color:var(--accent)}
    @media (max-width:1100px){.section-grid,.code-grid,.hero-meta{grid-template-columns:1fr}}
    @media print{
      body{background:#06111d !important;color:#dce9f7;padding:8px;-webkit-print-color-adjust:exact;print-color-adjust:exact}
      body::before{animation:none;right:-6px;top:12px;width:430px;opacity:.28;border-color:#2d5376;filter:saturate(1.04) contrast(1.16) brightness(.92)}
      body::after{right:24px;top:44px;width:350px;opacity:.16}
      .report-shell{max-width:none}
      .hero,.section,.stat-card,.table-frame,.code,pre{box-shadow:none;background:rgba(10,27,46,.78) !important;color:#dce9f7}
      .hero,.section,.table-frame,.code,pre,.stat-card{border-color:#264867}
      th{background:rgba(16,37,63,.82);color:#dce9f7}
      td{background:rgba(8,21,36,.48);color:#dce9f7}
      .muted,.meta,.meta-pill{color:#9eb6ce}
      .table-scroll thead th{position:static}
      .avoid-break{break-inside:avoid-page;page-break-inside:avoid}
    }
    ${extra}
  `;
}

function renderStatGrid(
  cards: Array<{ label: string; value: string | number; tone?: string; sub?: string }>,
): string {
  if (!cards.length) {
    return "";
  }
  return `<div class="stat-grid">${cards
    .map(
      (card) => `<article class="stat-card${card.tone ? ` tone-${escapeHtml(card.tone)}` : ""}">
        <span class="label">${escapeHtml(card.label)}</span>
        <span class="value">${escapeHtml(String(card.value))}</span>
        ${card.sub ? `<span class="sub">${escapeHtml(card.sub)}</span>` : ""}
      </article>`,
    )
    .join("")}</div>`;
}

function renderMetricBars(
  title: string,
  rows: Array<{ label: string; value: number; tone?: "critical" | "high" | "medium" | "low" | "info" | "accent" }>,
): string {
  const filtered = rows.filter((row) => Number.isFinite(row.value) && row.value >= 0);
  if (!filtered.length) {
    return `<p class="muted">No ${escapeHtml(title.toLowerCase())} data available.</p>`;
  }
  const max = Math.max(1, ...filtered.map((row) => row.value));
  const body = filtered
    .map((row) => {
      const width = Math.max(2, Math.round((row.value / max) * 100));
      return `<div class="kpi-row tone-${escapeHtml(row.tone || "accent")}">
        <div class="kpi-label" title="${escapeHtml(row.label)}">${escapeHtml(row.label)}</div>
        <div class="kpi-track"><div class="kpi-fill" style="width:${width}%"></div></div>
        <div class="kpi-value">${escapeHtml(String(row.value))}</div>
      </div>`;
    })
    .join("");
  return `<h3>${escapeHtml(title)}</h3><div class="kpi-bars">${body}</div>`;
}

function formatMetricNumber(value: unknown, digits = 2): string {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) {
    return "N/A";
  }
  return numeric.toFixed(digits);
}

function formatBestLikelyWorst(value: Record<string, unknown>): string {
  if (value.available === false) {
    return "N/A";
  }
  const best = value.best_case_usd ?? value.best_case_hours;
  const likely = value.most_likely_usd ?? value.most_likely_hours;
  const worst = value.worst_case_usd ?? value.worst_case_hours;
  const bestText = formatMetricNumber(best, Number.isInteger(Number(best)) ? 0 : 1);
  const likelyText = formatMetricNumber(likely, Number.isInteger(Number(likely)) ? 0 : 1);
  const worstText = formatMetricNumber(worst, Number.isInteger(Number(worst)) ? 0 : 1);
  if (bestText === "N/A" && likelyText === "N/A" && worstText === "N/A") {
    return "N/A";
  }
  return `${bestText} / ${likelyText} / ${worstText}`;
}

function objectSummaryRows(value: unknown): string {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return "";
  }
  return Object.entries(value as Record<string, unknown>)
    .map(([key, item]) => {
      const label = key.replaceAll("_", " ");
      const normalized =
        typeof item === "number"
          ? Number(item).toFixed(Number.isInteger(item) ? 0 : 2)
          : Array.isArray(item)
            ? item.map((part) => String(part)).join(", ")
            : item && typeof item === "object"
              ? Object.entries(item as Record<string, unknown>)
                  .map(([nestedKey, nestedValue]) => `${nestedKey}=${String(nestedValue)}`)
                  .join(", ")
            : String(item ?? "N/A");
      return `<tr><td>${escapeHtml(label)}</td><td>${escapeHtml(normalized)}</td></tr>`;
    })
    .join("");
}

type GroupedFalsePositiveRow = {
  issue: string;
  severity: string;
  locations: string;
  reason: string;
  detail: string;
  confidence: number;
};

function groupFalsePositiveRows(candidates: Array<Record<string, unknown>>): GroupedFalsePositiveRow[] {
  const grouped = new Map<string, { item: Record<string, unknown>; locations: string[]; confidence: number }>();
  for (const item of candidates) {
    const issue = String(item.vulnerability_title || "Issue");
    const reason = String(item.reason_summary || "N/A");
    const filePath = String(item.file_path || "unknown");
    const line = Number(item.line_number || 1);
    const location = `${filePath}:${line}`;
    const key = `${issue}::${reason}`;
    const confidence = Number(item.confidence || 0);
    const current = grouped.get(key);
    if (!current) {
      grouped.set(key, {
        item,
        locations: [location],
        confidence,
      });
      continue;
    }
    if (!current.locations.includes(location)) {
      current.locations.push(location);
    }
    if (confidence > current.confidence) {
      current.item = item;
      current.confidence = confidence;
    }
  }

  return Array.from(grouped.values())
    .map((entry) => ({
      issue: String(entry.item.vulnerability_title || "Issue"),
      severity: String(entry.item.severity || "Info"),
      locations:
        entry.locations.length > 4
          ? `${entry.locations.slice(0, 4).join(", ")} (+${entry.locations.length - 4} more)`
          : entry.locations.join(", "),
      reason: String(entry.item.reason_summary || "N/A"),
      detail: String(entry.item.reason_detail || "N/A"),
      confidence: Number(entry.confidence || 0),
    }))
    .sort((a, b) => b.confidence - a.confidence);
}

function escapeHtml(value: string): string {
  return String(value || "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll("\"", "&quot;")
    .replaceAll("'", "&#39;");
}

function escapeXml(value: string): string {
  return String(value || "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll("\"", "&quot;")
    .replaceAll("'", "&apos;");
}

function objectToXml(tag: string, value: unknown): string {
  if (value === null || value === undefined) {
    return `<${tag}></${tag}>`;
  }
  if (Array.isArray(value)) {
    const inner = value.map((item) => objectToXml("item", item)).join("");
    return `<${tag}>${inner}</${tag}>`;
  }
  if (typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>);
    const inner = entries.map(([key, item]) => objectToXml(slugXmlTag(key), item)).join("");
    return `<${tag}>${inner}</${tag}>`;
  }
  return `<${tag}>${escapeXml(String(value))}</${tag}>`;
}

function slugXmlTag(value: string): string {
  const normalized = String(value || "field")
    .trim()
    .replace(/[^A-Za-z0-9_]+/g, "_")
    .replace(/^([^A-Za-z_])/, "_$1");
  return normalized || "field";
}

function slugify(value: string): string {
  return value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 80);
}
