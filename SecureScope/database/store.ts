import { promises as fs } from "node:fs";
import path from "node:path";

import { randomUUID } from "node:crypto";

import { toHistoryItem, toScanView } from "../backend/reportAdapter";
import {
  AuditEntry,
  FindingReviewState,
  ScanHistoryItem,
  ScanRecord,
  ScanView,
  Severity,
  ToolchainStatusEntry,
  UserRole,
  UniversalScanReport,
  VulnerabilityFinding,
} from "../backend/types";

interface PersistedState {
  scans: ScanRecord[];
  audits: AuditEntry[];
}

type LooseRecord = Record<string, unknown>;

const MAX_SCAN_HISTORY = 20;
const MAX_AUDIT_HISTORY = 1000;
const MAX_STORE_BYTES = 32 * 1024 * 1024;
const MAX_LEGACY_DB_BYTES = 256 * 1024 * 1024;
const MAX_PERSIST_ATTEMPTS = 220;
const MAX_AUDIT_DETAIL_LENGTH = 1200;
const MAX_AUDIT_DETAIL_LENGTH_AGGRESSIVE = 420;
const MAX_FINDING_TEXT_LENGTH = 2200;
const MAX_PATCH_LENGTH = 4800;
const MAX_AUTOFIX_RECOMMENDATIONS = 300;
const MAX_AUTOFIX_RECOMMENDATIONS_AGGRESSIVE = 80;
const MIN_FINDINGS_AFTER_SHRINK = 100;
const USER_ROLE_SET = new Set<UserRole>(["Admin", "Security Analyst", "Developer", "Auditor"]);
const SEVERITY_SET = new Set<Severity>(["Critical", "High", "Medium", "Low", "Info"]);

export class ScanStore {
  private state: PersistedState;
  private readonly dbFile: string;

  private constructor(dbFile: string, state: PersistedState) {
    this.dbFile = dbFile;
    this.state = state;
  }

  static async create(dbFile: string): Promise<ScanStore> {
    await fs.mkdir(path.dirname(dbFile), { recursive: true });

    if (await isFileLargerThan(dbFile, MAX_LEGACY_DB_BYTES)) {
      await quarantineDbFile(dbFile);
    }

    try {
      const raw = await fs.readFile(dbFile, "utf-8");
      const parsed = JSON.parse(raw) as PersistedState;
      const store = new ScanStore(dbFile, normalizeState(parsed));
      await store.persist();
      return store;
    } catch {
      const initial: PersistedState = { scans: [], audits: [] };
      const store = new ScanStore(dbFile, initial);
      await store.persist();
      return store;
    }
  }

  async addScan(record: ScanRecord): Promise<void> {
    const compacted = compactScanRecord(record);
    this.state.scans = [compacted, ...this.state.scans].slice(0, MAX_SCAN_HISTORY);
    await this.persist();
  }

  listHistory(): ScanHistoryItem[] {
    return this.state.scans.map(toHistoryItem);
  }

  getScanView(scanId: string): ScanView | null {
    const record = this.state.scans.find((item) => item.scanId === scanId);
    if (!record) {
      return null;
    }
    return toScanView(record);
  }

  getFindingState(scanId: string, findingId: string): FindingReviewState | null {
    const record = this.state.scans.find((item) => item.scanId === scanId);
    if (!record) {
      return null;
    }
    return record.findingStates[findingId] || null;
  }

  async markReviewed(scanId: string, findingId: string, actor: string): Promise<ScanView | null> {
    const record = this.state.scans.find((item) => item.scanId === scanId);
    if (!record) {
      return null;
    }

    record.findingStates[findingId] = {
      status: "Reviewed",
      reviewedBy: actor,
      reviewedAt: new Date().toISOString(),
    };
    await this.persist();
    return toScanView(record);
  }

  async addAudit(payload: { scanId?: string; action: string; actor: string; role: UserRole; details: string }): Promise<void> {
    const entry: AuditEntry = {
      id: randomUUID(),
      scanId: payload.scanId,
      action: payload.action,
      actor: payload.actor,
      role: normalizeRole(payload.role),
      details: truncateText(payload.details, MAX_AUDIT_DETAIL_LENGTH),
      createdAt: new Date().toISOString(),
    };
    this.state.audits = [entry, ...this.state.audits].slice(0, MAX_AUDIT_HISTORY);
    await this.persist();
  }

  listAudits(scanId?: string): AuditEntry[] {
    if (!scanId) {
      return this.state.audits;
    }
    return this.state.audits.filter((item) => item.scanId === scanId);
  }

  private async persist(): Promise<void> {
    const tempFile = `${this.dbFile}.tmp`;
    this.enforceRetention();

    let attempts = 0;
    while (attempts < MAX_PERSIST_ATTEMPTS) {
      let serialized = "";
      try {
        serialized = JSON.stringify(this.state, null, 2);
      } catch {
        const reduced = this.reduceStateFootprint(true);
        if (!reduced) {
          this.resetStateMinimal();
        }
        attempts += 1;
        continue;
      }

      if (serialized.length <= MAX_STORE_BYTES) {
        await fs.writeFile(tempFile, serialized, "utf-8");
        await fs.rename(tempFile, this.dbFile);
        return;
      }

      const aggressive = serialized.length > MAX_STORE_BYTES * 2 || attempts > 24;
      const reduced = this.reduceStateFootprint(aggressive);
      if (!reduced) {
        this.resetStateMinimal();
      }
      attempts += 1;
    }

    // Final safety valve: keep a tiny operational store instead of throwing to UI.
    this.resetStateMinimal();
    const fallback = JSON.stringify(this.state, null, 2);
    await fs.writeFile(tempFile, fallback, "utf-8");
    await fs.rename(tempFile, this.dbFile);
  }

  private enforceRetention(): void {
    this.state.scans = this.state.scans.slice(0, MAX_SCAN_HISTORY).map((scan) => compactScanRecord(scan));
    this.state.audits = this.state.audits.slice(0, MAX_AUDIT_HISTORY).map((entry) => compactAuditEntry(entry));
  }

  private reduceStateFootprint(aggressive: boolean): boolean {
    let changed = false;

    if (this.state.scans.length > 1) {
      const dropCount = aggressive ? Math.max(1, Math.floor(this.state.scans.length * 0.35)) : 1;
      const nextLength = Math.max(1, this.state.scans.length - dropCount);
      this.state.scans = this.state.scans.slice(0, nextLength);
      changed = true;
    }

    const latest = this.state.scans[0];
    if (latest) {
      const findings = latest.report.vulnerability_fixed_code_report.findings || [];
      if (findings.length > MIN_FINDINGS_AFTER_SHRINK) {
        const ratio = aggressive ? 0.5 : 0.75;
        const keep = Math.max(MIN_FINDINGS_AFTER_SHRINK, Math.floor(findings.length * ratio));
        latest.report.vulnerability_fixed_code_report.findings = findings.slice(0, keep);
        latest.report.vulnerability_fixed_code_report.auto_fix_recommendations = latest.report.vulnerability_fixed_code_report.auto_fix_recommendations.slice(
          0,
          Math.min(keep, aggressive ? MAX_AUTOFIX_RECOMMENDATIONS_AGGRESSIVE : MAX_AUTOFIX_RECOMMENDATIONS),
        );
        latest.findingStates = compactFindingStates(latest.findingStates, latest.report.vulnerability_fixed_code_report.findings);
        syncReportSummary(latest.report);
        changed = true;
      } else if (latest.report.vulnerability_fixed_code_report.auto_fix_recommendations.length > MAX_AUTOFIX_RECOMMENDATIONS_AGGRESSIVE) {
        latest.report.vulnerability_fixed_code_report.auto_fix_recommendations = latest.report.vulnerability_fixed_code_report.auto_fix_recommendations.slice(
          0,
          MAX_AUTOFIX_RECOMMENDATIONS_AGGRESSIVE,
        );
        changed = true;
      }

      if (aggressive) {
        latest.report.vulnerability_fixed_code_report.findings = latest.report.vulnerability_fixed_code_report.findings.map((item) =>
          compactFinding(item, true),
        );
        latest.findingStates = compactFindingStates(latest.findingStates, latest.report.vulnerability_fixed_code_report.findings);
        syncReportSummary(latest.report);
        changed = true;
      }
    }

    const minAudits = aggressive ? 80 : 200;
    if (this.state.audits.length > minAudits) {
      const keep = aggressive ? Math.max(80, Math.floor(this.state.audits.length * 0.5)) : Math.max(200, Math.floor(this.state.audits.length * 0.75));
      this.state.audits = this.state.audits.slice(0, keep);
      changed = true;
    }

    this.state.audits = this.state.audits.map((entry) => compactAuditEntry(entry, aggressive));
    return changed;
  }

  private resetStateMinimal(): void {
    const latest = this.state.scans[0] ? compactScanRecord(this.state.scans[0]) : null;
    if (latest) {
      latest.report.vulnerability_fixed_code_report.findings = latest.report.vulnerability_fixed_code_report.findings.slice(
        0,
        MIN_FINDINGS_AFTER_SHRINK,
      );
      latest.report.vulnerability_fixed_code_report.auto_fix_recommendations = [];
      latest.findingStates = compactFindingStates(latest.findingStates, latest.report.vulnerability_fixed_code_report.findings);
      syncReportSummary(latest.report);
      this.state.scans = [latest];
    } else {
      this.state.scans = [];
    }

    this.state.audits = this.state.audits.slice(0, 80).map((entry) => compactAuditEntry(entry, true));
  }
}

function normalizeState(input: PersistedState): PersistedState {
  const rawScans = Array.isArray(input?.scans) ? input.scans : [];
  const rawAudits = Array.isArray(input?.audits) ? input.audits : [];

  const scans = rawScans.slice(0, MAX_SCAN_HISTORY).map((scan) => compactScanRecord(scan));
  const audits = rawAudits.slice(0, MAX_AUDIT_HISTORY).map((entry) => compactAuditEntry(entry));

  return { scans, audits };
}

function compactScanRecord(input: Partial<ScanRecord> | LooseRecord): ScanRecord {
  const raw = asRecord(input);
  const report = compactReport(raw.report);
  const findingStates = compactFindingStates(raw.findingStates, report.vulnerability_fixed_code_report.findings);

  return {
    scanId: asString(raw.scanId, randomUUID()),
    projectPath: asString(raw.projectPath, "unknown"),
    requestedBy: truncateText(asString(raw.requestedBy, "local-user"), 180),
    role: normalizeRole(raw.role),
    startedAt: normalizeIso(raw.startedAt),
    completedAt: normalizeIso(raw.completedAt),
    report,
    findingStates,
  };
}

function compactReport(input: unknown): UniversalScanReport {
  const raw = asRecord(input);
  const scanner = asRecord(raw.scanner);
  const executive = asRecord(raw.executive_summary);
  const existing = asRecord(raw.existing_implementation_report);
  const existingSummary = asRecord(existing.summary);
  const vulnerability = asRecord(raw.vulnerability_fixed_code_report);
  const vulnerabilitySummary = asRecord(vulnerability.summary);

  const findings = asArray(vulnerability.findings).map((item) => compactFinding(item));
  const severityDistribution = normalizeSeverityDistribution(
    vulnerabilitySummary.severity_distribution,
    normalizeSeverityDistribution(executive.severity_distribution, summarizeSeverity(findings)),
  );

  const controls = asArray(existing.controls).map((item) => {
    const control = asRecord(item);
    return {
      control_id: asString(control.control_id, "CTRL-UNKNOWN"),
      name: asString(control.name, "Unnamed Control"),
      category: asString(control.category, "General"),
      description: truncateText(asString(control.description, ""), 1200),
      status: asString(control.status, "Implemented"),
      coverage_level: asString(control.coverage_level, "Low"),
      standard_mappings: asArray(control.standard_mappings).map((mapping) => asString(mapping)).filter(Boolean).slice(0, 20),
      evidence: asArray(control.evidence)
        .filter((entry) => typeof entry === "object" && entry !== null)
        .map((entry) => sanitizeUnknownValue(entry, 2) as Record<string, unknown>)
        .slice(0, 40),
    };
  });

  const complianceMatrix = asArray(existing.compliance_matrix).map((item) => {
    const row = asRecord(item);
    return {
      standard: asString(row.standard, "N/A"),
      control_count: asNumber(row.control_count, 0),
      status: asString(row.status, "partial"),
    };
  });

  const toolchainStatusInput = asRecord(vulnerability.toolchain_status);
  const toolchainStatus: Record<string, ToolchainStatusEntry> = {};
  for (const [name, value] of Object.entries(toolchainStatusInput)) {
    const tool = asRecord(value);
    toolchainStatus[name] = {
      name: asString(tool.name, name),
      available: Boolean(tool.available),
      command: asString(tool.command, name),
      source: asString(tool.source, "unknown"),
      message: truncateText(asString(tool.message, ""), 500),
      selected: Boolean(tool.selected),
      runner_available: Boolean(tool.runner_available),
      display_name: asString(tool.display_name, ""),
      description: truncateText(asString(tool.description, ""), 500),
      category: asString(tool.category, ""),
      target_modes: asArray(tool.target_modes).map((item) => asString(item)).filter(Boolean).slice(0, 8),
      vulnerability_classes: asArray(tool.vulnerability_classes).map((item) => asString(item)).filter(Boolean).slice(0, 20),
      homepage: asString(tool.homepage, ""),
      integrated: Boolean(tool.integrated),
      recommended_command: asString(tool.recommended_command, ""),
    };
  }

  const autoFixRecommendations = asArray(vulnerability.auto_fix_recommendations)
    .map((item) => sanitizeUnknownValue(item, 2))
    .filter((item) => isPlainObject(item))
    .map((item) => item as Record<string, unknown>)
    .slice(0, MAX_AUTOFIX_RECOMMENDATIONS);

  const report: UniversalScanReport = {
    scanner: {
      name: asString(scanner.name, "CodeSentinelX"),
      version: asString(scanner.version, "1.0.0"),
    },
    executive_summary: {
      target_path: asString(executive.target_path, "unknown"),
      generated_at: normalizeIso(executive.generated_at),
      files_scanned: asNumber(executive.files_scanned, 0),
      total_vulnerabilities: asNumber(executive.total_vulnerabilities, findings.length),
      deduplicated_vulnerabilities: asOptionalNumber(executive.deduplicated_vulnerabilities),
      duplicate_findings_removed: asOptionalNumber(executive.duplicate_findings_removed),
      total_files_impacted: asOptionalNumber(executive.total_files_impacted),
      active_risk_findings: asOptionalNumber(executive.active_risk_findings),
      assessment_confidence: asOptionalString(executive.assessment_confidence),
      severity_distribution: severityDistribution,
      risk_score: asNumber(executive.risk_score, 0),
      risk_rating: asString(executive.risk_rating, "Informational"),
      top_vulnerability_types: normalizeTopTypeRows(executive.top_vulnerability_types),
      top_owasp_categories: normalizeTopOwaspRows(executive.top_owasp_categories),
      affected_modules: normalizeAffectedModuleRows(executive.affected_modules),
      recommended_action_plan: asArray(executive.recommended_action_plan).map((item) => truncateText(asString(item), 400)).filter(Boolean).slice(0, 20),
      implemented_controls: asOptionalNumber(executive.implemented_controls),
    },
    existing_implementation_report: {
      report_type: "existing_implementation",
      title: asString(existing.title, "Existing Security Implementation Report"),
      target_path: asString(existing.target_path, asString(executive.target_path, "unknown")),
      generated_at: normalizeIso(existing.generated_at || executive.generated_at),
      summary: {
        implemented_controls: asNumber(existingSummary.implemented_controls, controls.length),
        category_distribution: normalizeCountMap(existingSummary.category_distribution),
        coverage_levels: normalizeCountMap(existingSummary.coverage_levels),
        standards_coverage: normalizeCountMap(existingSummary.standards_coverage),
      },
      controls,
      compliance_matrix: complianceMatrix,
    },
    vulnerability_fixed_code_report: {
      report_type: "vulnerability_fixed_code",
      title: asString(vulnerability.title, "Vulnerability and Fixed-Code Report"),
      target_path: asString(vulnerability.target_path, asString(executive.target_path, "unknown")),
      generated_at: normalizeIso(vulnerability.generated_at || executive.generated_at),
      summary: {
        total_findings: findings.length,
        raw_findings_total: asNumber(vulnerabilitySummary.raw_findings_total, findings.length),
        duplicate_findings_removed: asNumber(vulnerabilitySummary.duplicate_findings_removed, 0),
        severity_distribution: severityDistribution,
        risk_score: asNumber(vulnerabilitySummary.risk_score, asNumber(executive.risk_score, 0)),
        risk_rating: asString(vulnerabilitySummary.risk_rating, asString(executive.risk_rating, "Informational")),
        active_risk_findings: asNumber(vulnerabilitySummary.active_risk_findings, 0),
        files_impacted: asNumber(vulnerabilitySummary.files_impacted, new Set(findings.map((item) => item.file_path)).size),
        top_vulnerability_types: normalizeTopTypeRows(vulnerabilitySummary.top_vulnerability_types),
        top_owasp_categories: normalizeTopOwaspRows(vulnerabilitySummary.top_owasp_categories),
        affected_modules: normalizeAffectedModuleRows(vulnerabilitySummary.affected_modules),
        open_findings: asOptionalNumber(vulnerabilitySummary.open_findings),
        reviewed_findings: asOptionalNumber(vulnerabilitySummary.reviewed_findings),
      },
      findings,
      auto_fix_recommendations: autoFixRecommendations,
      toolchain_status: toolchainStatus,
    },
  };

  syncReportSummary(report);
  return report;
}

function compactFinding(input: unknown, aggressive = false): VulnerabilityFinding {
  const raw = asRecord(input);
  const severity = normalizeSeverity(raw.severity);
  const textLimit = aggressive ? Math.floor(MAX_FINDING_TEXT_LENGTH * 0.6) : MAX_FINDING_TEXT_LENGTH;
  const patchLimit = aggressive ? Math.floor(MAX_PATCH_LENGTH * 0.55) : MAX_PATCH_LENGTH;

  return {
    finding_uid: asString(raw.finding_uid, ""),
    vulnerability_title: truncateText(asString(raw.vulnerability_title, asString(raw.vulnerability_type, "Security Finding")), textLimit),
    vulnerability_type: truncateText(asString(raw.vulnerability_type, ""), textLimit),
    description: truncateText(asString(raw.description, ""), textLimit),
    severity,
    cvss_score: asNumber(raw.cvss_score, severityToCvss(severity)),
    cwe_id: asString(raw.cwe_id, "N/A"),
    owasp_mapping: asString(raw.owasp_mapping, "N/A"),
    file_path: asString(raw.file_path, "unknown"),
    line_number: Math.max(1, asNumber(raw.line_number, 1)),
    business_impact: truncateText(asString(raw.business_impact, ""), textLimit),
    recommendation: truncateText(asString(raw.recommendation, ""), textLimit),
    original_code: truncateText(asString(raw.original_code, ""), textLimit),
    fixed_code: truncateText(asString(raw.fixed_code, ""), textLimit),
    patch_preview: truncateText(asString(raw.patch_preview, ""), patchLimit),
    rule_id: asString(raw.rule_id, "rule"),
    evidence_sources: asArray(raw.evidence_sources).map((item) => asString(item)).filter(Boolean).slice(0, 20),
    affected_module: asOptionalString(raw.affected_module),
    tool: asOptionalString(raw.tool),
    status: raw.status === "Reviewed" ? "Reviewed" : "Open",
    reviewed_by: asOptionalString(raw.reviewed_by),
    reviewed_at: asOptionalString(raw.reviewed_at),
  };
}

function compactFindingStates(
  input: unknown,
  findings: VulnerabilityFinding[],
): Record<string, FindingReviewState> {
  const source = asRecord(input);
  const allowedIds = new Set<string>(findings.map((item) => buildFindingIdentity(item)));
  const result: Record<string, FindingReviewState> = {};

  for (const [key, value] of Object.entries(source)) {
    if (!allowedIds.has(key)) {
      continue;
    }
    const state = asRecord(value);
    const normalizedStatus = state.status === "Reviewed" ? "Reviewed" : "Open";
    if (normalizedStatus === "Open") {
      continue;
    }
    result[key] = {
      status: normalizedStatus,
      reviewedBy: truncateText(asString(state.reviewedBy || state.review_by || ""), 180),
      reviewedAt: normalizeIso(state.reviewedAt || state.reviewed_at),
    };
  }

  return result;
}

function compactAuditEntry(input: Partial<AuditEntry> | LooseRecord, aggressive = false): AuditEntry {
  const raw = asRecord(input);
  return {
    id: asString(raw.id, randomUUID()),
    scanId: asOptionalString(raw.scanId),
    action: truncateText(asString(raw.action, "unknown"), 120),
    actor: truncateText(asString(raw.actor, "local-user"), 180),
    role: normalizeRole(raw.role),
    details: truncateText(asString(raw.details, ""), aggressive ? MAX_AUDIT_DETAIL_LENGTH_AGGRESSIVE : MAX_AUDIT_DETAIL_LENGTH),
    createdAt: normalizeIso(raw.createdAt),
  };
}

function syncReportSummary(report: UniversalScanReport): void {
  const findings = report.vulnerability_fixed_code_report.findings || [];
  const severityDistribution = summarizeSeverity(findings);
  const filesImpacted = new Set(findings.map((item) => item.file_path)).size;
  const reviewed = findings.filter((item) => item.status === "Reviewed").length;
  const open = Math.max(0, findings.length - reviewed);

  report.vulnerability_fixed_code_report.summary.total_findings = findings.length;
  report.vulnerability_fixed_code_report.summary.raw_findings_total = Math.max(
    findings.length,
    asNumber(report.vulnerability_fixed_code_report.summary.raw_findings_total, findings.length),
  );
  report.vulnerability_fixed_code_report.summary.severity_distribution = severityDistribution;
  report.vulnerability_fixed_code_report.summary.files_impacted = filesImpacted;
  report.vulnerability_fixed_code_report.summary.active_risk_findings =
    (severityDistribution.Critical || 0) + (severityDistribution.High || 0);
  report.vulnerability_fixed_code_report.summary.open_findings = open;
  report.vulnerability_fixed_code_report.summary.reviewed_findings = reviewed;

  report.executive_summary.total_vulnerabilities = findings.length;
  report.executive_summary.severity_distribution = { ...severityDistribution };
  report.executive_summary.total_files_impacted = filesImpacted;
  report.executive_summary.active_risk_findings = (severityDistribution.Critical || 0) + (severityDistribution.High || 0);
}

function buildFindingIdentity(finding: VulnerabilityFinding): string {
  if (finding.finding_uid && finding.finding_uid.trim().length > 0) {
    return finding.finding_uid;
  }
  const ruleId = finding.rule_id || "rule";
  return `${ruleId}::${finding.file_path}::${finding.line_number}`;
}

function normalizeRole(value: unknown): UserRole {
  const candidate = asString(value, "Security Analyst") as UserRole;
  return USER_ROLE_SET.has(candidate) ? candidate : "Security Analyst";
}

function normalizeSeverity(value: unknown): Severity {
  const candidate = asString(value, "Info") as Severity;
  if (SEVERITY_SET.has(candidate)) {
    return candidate;
  }

  const lowered = candidate.toLowerCase();
  if (lowered.startsWith("crit")) {
    return "Critical";
  }
  if (lowered.startsWith("high")) {
    return "High";
  }
  if (lowered.startsWith("med")) {
    return "Medium";
  }
  if (lowered.startsWith("low")) {
    return "Low";
  }
  return "Info";
}

function normalizeSeverityDistribution(input: unknown, fallback?: Record<string, number>): Record<string, number> {
  const source = asRecord(input);
  const base = fallback || { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };
  return {
    Critical: asNumber(source.Critical, base.Critical || 0),
    High: asNumber(source.High, base.High || 0),
    Medium: asNumber(source.Medium, base.Medium || 0),
    Low: asNumber(source.Low, base.Low || 0),
    Info: asNumber(source.Info, base.Info || 0),
  };
}

function summarizeSeverity(findings: VulnerabilityFinding[]): Record<string, number> {
  const distribution: Record<string, number> = {
    Critical: 0,
    High: 0,
    Medium: 0,
    Low: 0,
    Info: 0,
  };

  for (const finding of findings) {
    distribution[finding.severity] = (distribution[finding.severity] || 0) + 1;
  }

  return distribution;
}

function normalizeTopTypeRows(input: unknown): Array<{ type: string; count: number }> {
  return asArray(input)
    .map((item) => {
      const row = asRecord(item);
      return {
        type: asString(row.type, "N/A"),
        count: asNumber(row.count, 0),
      };
    })
    .filter((item) => item.type)
    .slice(0, 20);
}

function normalizeTopOwaspRows(input: unknown): Array<{ owasp_category: string; count: number }> {
  return asArray(input)
    .map((item) => {
      const row = asRecord(item);
      return {
        owasp_category: asString(row.owasp_category, "N/A"),
        count: asNumber(row.count, 0),
      };
    })
    .filter((item) => item.owasp_category)
    .slice(0, 20);
}

function normalizeAffectedModuleRows(input: unknown): Array<{ module: string; count: number; critical: number; high: number }> {
  return asArray(input)
    .map((item) => {
      const row = asRecord(item);
      return {
        module: asString(row.module, "unknown"),
        count: asNumber(row.count, 0),
        critical: asNumber(row.critical, 0),
        high: asNumber(row.high, 0),
      };
    })
    .filter((item) => item.module)
    .slice(0, 40);
}

function normalizeCountMap(input: unknown): Record<string, number> {
  const source = asRecord(input);
  const result: Record<string, number> = {};
  for (const [key, value] of Object.entries(source)) {
    result[String(key)] = asNumber(value, 0);
  }
  return result;
}

function sanitizeUnknownValue(value: unknown, depth: number): unknown {
  if (depth <= 0) {
    return undefined;
  }
  if (value === null || value === undefined) {
    return value;
  }
  if (typeof value === "string") {
    return truncateText(value, 1200);
  }
  if (typeof value === "number" || typeof value === "boolean") {
    return value;
  }
  if (Array.isArray(value)) {
    return value.map((item) => sanitizeUnknownValue(item, depth - 1)).slice(0, 30);
  }
  if (typeof value === "object") {
    const output: Record<string, unknown> = {};
    for (const [key, item] of Object.entries(value as Record<string, unknown>).slice(0, 30)) {
      output[key] = sanitizeUnknownValue(item, depth - 1);
    }
    return output;
  }
  return String(value);
}

function asRecord(value: unknown): LooseRecord {
  if (!isPlainObject(value)) {
    return {};
  }
  return value as LooseRecord;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function asString(value: unknown, fallback = ""): string {
  if (typeof value === "string") {
    return value;
  }
  if (value === null || value === undefined) {
    return fallback;
  }
  return String(value);
}

function asOptionalString(value: unknown): string | undefined {
  const text = asString(value, "").trim();
  return text.length > 0 ? text : undefined;
}

function asNumber(value: unknown, fallback = 0): number {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) {
    return fallback;
  }
  return parsed;
}

function asOptionalNumber(value: unknown): number | undefined {
  if (value === null || value === undefined || value === "") {
    return undefined;
  }
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : undefined;
}

function normalizeIso(value: unknown): string {
  const raw = asString(value, "").trim();
  if (!raw) {
    return new Date().toISOString();
  }
  const parsed = new Date(raw);
  if (Number.isNaN(parsed.getTime())) {
    return new Date().toISOString();
  }
  return parsed.toISOString();
}

function severityToCvss(severity: Severity): number {
  switch (severity) {
    case "Critical":
      return 9.8;
    case "High":
      return 8.2;
    case "Medium":
      return 6.1;
    case "Low":
      return 3.7;
    default:
      return 0;
  }
}

function truncateText(value: unknown, maxLength: number): string {
  const text = asString(value, "");
  if (text.length <= maxLength) {
    return text;
  }
  return `${text.slice(0, maxLength)}...`;
}

async function isFileLargerThan(filePath: string, maxBytes: number): Promise<boolean> {
  try {
    const stat = await fs.stat(filePath);
    return stat.size > maxBytes;
  } catch {
    return false;
  }
}

async function quarantineDbFile(dbFile: string): Promise<void> {
  try {
    const stamp = new Date().toISOString().replaceAll(":", "-").replaceAll(".", "-");
    const backupPath = `${dbFile}.oversize-${stamp}.bak`;
    await fs.rename(dbFile, backupPath);
  } catch {
    // Ignore rename issues; startup can still proceed with normal create flow.
  }
}
