import { promises as fs } from "node:fs";
import path from "node:path";

import { randomUUID } from "node:crypto";

import { toHistoryItem, toProjectedScanView, toScanView } from "../backend/reportAdapter";
import { buildCanonicalScanObject, normalizeUserRole } from "../backend/roleProjection";
import {
  AuditEntry,
  CanonicalScanObject,
  EnterpriseAssuranceSummary,
  FalsePositiveReport,
  FindingReviewState,
  PortfolioSummary,
  RoleProjectionMetadata,
  RoleAwareReport,
  ScanPreset,
  ScanHistoryItem,
  ScanRecord,
  ScanView,
  Severity,
  ToolExecutionStatus,
  ToolchainExecutionSummary,
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
const USER_ROLE_SET = new Set<UserRole>(["Admin", "Security Analyst", "Developer", "Auditor", "Management"]);
const SEVERITY_SET = new Set<Severity>(["Critical", "High", "Medium", "Low", "Info"]);
const SEVERITY_VALUES: Severity[] = ["Critical", "High", "Medium", "Low", "Info"];

export class ScanStore {
  private state: PersistedState;
  private readonly dbFile: string;
  private persistChain: Promise<void> = Promise.resolve();

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
    await this.persistQueued();
  }

  listHistory(): ScanHistoryItem[] {
    return this.state.scans.map(toHistoryItem);
  }

  getPortfolioSummary(): PortfolioSummary {
    return buildPortfolioSummary(this.state.scans);
  }

  getScanView(scanId: string, role?: UserRole): ScanView | null {
    const record = this.state.scans.find((item) => item.scanId === scanId);
    if (!record) {
      return null;
    }
    if (role) {
      return toProjectedScanView(record, normalizeRole(role));
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
    await this.persistQueued();
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
    await this.persistQueued();
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
        refreshCanonicalScan(latest);
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
        refreshCanonicalScan(latest);
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
      refreshCanonicalScan(latest);
      this.state.scans = [latest];
    } else {
      this.state.scans = [];
    }

    this.state.audits = this.state.audits.slice(0, 80).map((entry) => compactAuditEntry(entry, true));
  }

  private async persistQueued(): Promise<void> {
    const next = this.persistChain.then(() => this.persist());
    this.persistChain = next.catch(() => undefined);
    await next;
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
  const scanId = asString(raw.scanId, randomUUID());
  const projectPath = asString(raw.projectPath, "unknown");
  const role = normalizeRole(raw.role);
  const startedAt = normalizeIso(raw.startedAt);
  const completedAt = normalizeIso(raw.completedAt);
  const scanPreset = normalizeScanPreset(report.executive_summary.scan_preset);
  const canonicalScan = normalizeCanonicalScan(raw.canonicalScan, {
    scanId,
    projectPath,
    requestedRole: role,
    scanPreset,
    startedAt,
    completedAt,
    report,
  });

  return {
    scanId,
    projectPath,
    requestedBy: truncateText(asString(raw.requestedBy, "local-user"), 180),
    role,
    startedAt,
    completedAt,
    canonicalScan,
    projectionCache: normalizeProjectionCache(raw.projectionCache),
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
  const vulnerabilityFindings = asRecord(raw.vulnerability_findings);
  const vulnerabilityFindingsSummary = asRecord(vulnerabilityFindings.summary);

  const findings = asArray(vulnerability.findings).map((item) => compactFinding(item));
  const severityDistribution = normalizeSeverityDistribution(
    vulnerabilitySummary.severity_distribution,
    normalizeSeverityDistribution(
      vulnerabilityFindingsSummary.severity_distribution,
      normalizeSeverityDistribution(executive.severity_distribution, summarizeSeverity(findings)),
    ),
  );
  const totalFindings = asNumber(
    vulnerabilitySummary.total_findings,
    asNumber(vulnerabilityFindingsSummary.total, findings.length),
  );
  const rawFindingsTotal = asNumber(
    vulnerabilitySummary.raw_findings_total,
    asNumber(vulnerabilityFindingsSummary.raw_total, Math.max(findings.length, totalFindings)),
  );
  const duplicateFindingsRemoved = asNumber(
    vulnerabilitySummary.duplicate_findings_removed,
    asNumber(vulnerabilityFindingsSummary.duplicate_reduction, 0),
  );
  const filesImpacted = asNumber(
    vulnerabilitySummary.files_impacted,
    asNumber(existingSummary.files_impacted, new Set(findings.map((item) => item.file_path)).size),
  );
  const activeRiskFindings = asNumber(
    vulnerabilitySummary.active_risk_findings,
    (severityDistribution.Critical || 0) + (severityDistribution.High || 0),
  );
  const reviewedFindings = asOptionalNumber(vulnerabilitySummary.reviewed_findings) ?? asNumber(vulnerabilityFindingsSummary.reviewed_findings, 0);
  const openFindings = asOptionalNumber(vulnerabilitySummary.open_findings) ?? asNumber(vulnerabilityFindingsSummary.open_findings, Math.max(0, totalFindings - reviewedFindings));

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
      execution: normalizeToolExecutionStatus(tool.execution),
    };
  }

  const autoFixRecommendations = asArray(vulnerability.auto_fix_recommendations)
    .map((item) => sanitizeUnknownValue(item, 2))
    .filter((item) => isPlainObject(item))
    .map((item) => item as Record<string, unknown>)
    .slice(0, MAX_AUTOFIX_RECOMMENDATIONS);

  const profileCompliance =
    normalizeProfileCompliance(raw.profile_compliance) ||
    normalizeProfileCompliance(existing.profile_compliance);
  const enterpriseAssurance =
    normalizeEnterpriseAssurance(vulnerabilitySummary.enterprise_assurance) ||
    normalizeEnterpriseAssurance(executive.enterprise_assurance) ||
    normalizeEnterpriseAssurance(existing.enterprise_assurance);
  const toolchainExecution =
    normalizeToolchainExecutionSummary(vulnerabilitySummary.toolchain_execution) ||
    normalizeToolchainExecutionSummary(executive.toolchain_execution);
  const activePocSummary = normalizeActivePocSummary(vulnerabilitySummary.active_poc);
  const releaseGateDistribution = normalizeCountMap(vulnerabilitySummary.release_gate_distribution);
  const releaseGateDistributionFallback = Object.keys(releaseGateDistribution).length
    ? releaseGateDistribution
    : normalizeCountMap(executive.release_gate_distribution);
  const riskIntelligence =
    normalizeRiskIntelligence(vulnerabilitySummary.risk_intelligence) ||
    normalizeRiskIntelligence(executive.risk_intelligence);
  const gitDiffTracking =
    normalizeGitDiffTracking(vulnerabilitySummary.git_diff_tracking) ||
    normalizeGitDiffTracking(executive.git_diff_tracking);
  const authAbuseSessionSecurity =
    normalizeAuthAbuseSessionSecurity(vulnerabilitySummary.auth_abuse_session_security) ||
    normalizeAuthAbuseSessionSecurity(executive.auth_abuse_session_security);
  const falsePositiveReport =
    normalizeFalsePositiveReport(raw.false_positive_report) ||
    normalizeFalsePositiveReport(vulnerability.false_positive_report) ||
    normalizeFalsePositiveReport(vulnerabilitySummary.false_positive_report);
  const roleAwareReport =
    normalizeRoleAwareReport(raw.role_aware_report) ||
    normalizeRoleAwareReport(vulnerability.role_aware_report) ||
    normalizeRoleAwareReport(vulnerabilitySummary.role_aware_report);
  const deterministicReplay =
    normalizeDeterministicReplay(vulnerabilitySummary.deterministic_replay) ||
    normalizeDeterministicReplay(vulnerability.deterministic_replay) ||
    normalizeDeterministicReplay(executive.deterministic_replay);
  const reportIntegrityChain =
    normalizeReportIntegrityChain(vulnerabilitySummary.report_integrity_chain) ||
    normalizeReportIntegrityChain(vulnerability.report_integrity_chain) ||
    normalizeReportIntegrityChain(executive.report_integrity_chain);
  const policyWorkflow =
    normalizeCompactObject(vulnerabilitySummary.policy_workflow) ||
    normalizeCompactObject(executive.policy_workflow);
  const suppressionLifecycle =
    normalizeCompactObject(vulnerabilitySummary.suppression_lifecycle) ||
    normalizeCompactObject(executive.suppression_lifecycle);
  const managementSummary = asRecord(executive.management_summary);
  const vulnerabilityManagementSummary = asRecord(vulnerabilityFindings.summary);
  const managementSeverityBreakdownGroups = asArray(managementSummary.severity_breakdown_groups).map((item) => asRecord(item));
  const vulnerabilitySeverityBreakdownGroups = asArray(vulnerabilityManagementSummary.severity_breakdown_groups).map((item) => asRecord(item));
  const managementSummaryPayload = {
    total_findings: asNumber(managementSummary.total_findings, asNumber(vulnerabilityManagementSummary.total_findings, totalFindings)),
    deduplicated_vulnerabilities: asNumber(
      managementSummary.deduplicated_vulnerabilities,
      asNumber(vulnerabilityManagementSummary.deduplicated_vulnerabilities, totalFindings),
    ),
    active_risk_findings: asNumber(
      managementSummary.active_risk_findings,
      asNumber(vulnerabilityManagementSummary.active_risk_findings, activeRiskFindings),
    ),
    severity_distribution: normalizeSeverityDistribution(
      managementSummary.severity_distribution,
      normalizeSeverityDistribution(vulnerabilityManagementSummary.severity_distribution, severityDistribution),
    ),
    severity_distribution_raw: normalizeSeverityDistribution(
      managementSummary.severity_distribution_raw,
      normalizeSeverityDistribution(vulnerabilityManagementSummary.severity_distribution_raw, severityDistribution),
    ),
    severity_breakdown_groups: managementSeverityBreakdownGroups.length
      ? managementSeverityBreakdownGroups
      : vulnerabilitySeverityBreakdownGroups,
    top_vulnerability_types: normalizeTopTypeRows(managementSummary.top_vulnerability_types || vulnerabilityManagementSummary.top_vulnerability_types),
    top_owasp_categories: normalizeTopOwaspRows(managementSummary.top_owasp_categories || vulnerabilityManagementSummary.top_owasp_categories),
    affected_modules: normalizeAffectedModuleRows(managementSummary.affected_modules || vulnerabilityManagementSummary.affected_modules),
    affected_files: normalizeAffectedFileRows(managementSummary.affected_files || vulnerabilityManagementSummary.affected_files),
    affected_folders: normalizeAffectedFolderRows(managementSummary.affected_folders || vulnerabilityManagementSummary.affected_folders),
    risk_score: asNumber(managementSummary.risk_score, asNumber(vulnerabilityManagementSummary.risk_score, asNumber(executive.risk_score, 0))),
    risk_rating: asString(managementSummary.risk_rating, asString(vulnerabilityManagementSummary.risk_rating, asString(executive.risk_rating, "Informational"))),
  };

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
      toolchain_execution: toolchainExecution,
      enterprise_assurance: enterpriseAssurance,
      deterministic_replay: deterministicReplay,
      report_integrity_chain: reportIntegrityChain,
      policy_workflow: policyWorkflow,
      suppression_lifecycle: suppressionLifecycle,
      management_summary: managementSummaryPayload,
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
      profile_compliance: profileCompliance,
      enterprise_assurance: enterpriseAssurance,
    },
    vulnerability_fixed_code_report: {
      report_type: "vulnerability_fixed_code",
      title: asString(vulnerability.title, "Vulnerability and Fixed-Code Report"),
      target_path: asString(vulnerability.target_path, asString(executive.target_path, "unknown")),
      generated_at: normalizeIso(vulnerability.generated_at || executive.generated_at),
      summary: {
        total_findings: totalFindings,
        raw_findings_total: rawFindingsTotal,
        duplicate_findings_removed: duplicateFindingsRemoved,
        severity_distribution: severityDistribution,
        risk_score: asNumber(vulnerabilitySummary.risk_score, asNumber(executive.risk_score, 0)),
        risk_rating: asString(vulnerabilitySummary.risk_rating, asString(executive.risk_rating, "Informational")),
        active_risk_findings: activeRiskFindings,
        files_impacted: filesImpacted,
        top_vulnerability_types: normalizeTopTypeRows(vulnerabilitySummary.top_vulnerability_types),
        top_owasp_categories: normalizeTopOwaspRows(vulnerabilitySummary.top_owasp_categories),
        affected_modules: normalizeAffectedModuleRows(vulnerabilitySummary.affected_modules),
        release_gate_distribution: releaseGateDistributionFallback,
        risk_intelligence: riskIntelligence,
        git_diff_tracking: gitDiffTracking,
        auth_abuse_session_security: authAbuseSessionSecurity,
        open_findings: openFindings,
        reviewed_findings: reviewedFindings,
        toolchain_execution: toolchainExecution,
        enterprise_assurance: enterpriseAssurance,
        active_poc: activePocSummary,
        false_positive_candidates: asOptionalNumber(vulnerabilitySummary.false_positive_candidates),
        deterministic_replay: deterministicReplay,
        report_integrity_chain: reportIntegrityChain,
        policy_workflow: policyWorkflow,
        suppression_lifecycle: suppressionLifecycle,
      },
      findings,
      auto_fix_recommendations: autoFixRecommendations,
      toolchain_status: toolchainStatus,
      false_positive_report: falsePositiveReport,
      role_aware_report: roleAwareReport,
      deterministic_replay: deterministicReplay,
      report_integrity_chain: reportIntegrityChain,
    },
    profile_compliance: profileCompliance,
    false_positive_report: falsePositiveReport,
    role_aware_report: roleAwareReport,
  };

  syncReportSummary(report);
  return report;
}

function compactFinding(input: unknown, aggressive = false): VulnerabilityFinding {
  const raw = asRecord(input);
  const severity = normalizeSeverity(raw.severity);
  const textLimit = aggressive ? Math.floor(MAX_FINDING_TEXT_LENGTH * 0.6) : MAX_FINDING_TEXT_LENGTH;
  const patchLimit = aggressive ? Math.floor(MAX_PATCH_LENGTH * 0.55) : MAX_PATCH_LENGTH;
  const pocLimit = aggressive ? Math.floor(MAX_FINDING_TEXT_LENGTH * 0.45) : Math.floor(MAX_FINDING_TEXT_LENGTH * 0.75);

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
    ai_suggested_fix: asOptionalString(truncateText(asString(raw.ai_suggested_fix, ""), textLimit)),
    ai_remediation_summary: asOptionalString(truncateText(asString(raw.ai_remediation_summary, ""), textLimit)),
    ai_validation_steps: asOptionalString(truncateText(asString(raw.ai_validation_steps, ""), textLimit)),
    ai_fix_source: asOptionalString(truncateText(asString(raw.ai_fix_source, ""), 200)),
    ai_fix_confidence_label: asOptionalString(truncateText(asString(raw.ai_fix_confidence_label, ""), 32)),
    ai_fix_confidence_score: asOptionalNumber(raw.ai_fix_confidence_score),
    ai_fix_grounded: raw.ai_fix_grounded === undefined ? undefined : Boolean(raw.ai_fix_grounded),
    ai_grounding_notes: asOptionalString(truncateText(asString(raw.ai_grounding_notes, ""), textLimit)),
    remediation_confidence: asOptionalString(asString(raw.remediation_confidence || raw.autofix_confidence || "", "")),
    code_evidence_excerpt: asOptionalString(truncateText(asString(raw.code_evidence_excerpt, ""), textLimit)),
    source_line_snippet: asOptionalString(truncateText(asString(raw.source_line_snippet, ""), textLimit)),
    code_owner: asOptionalString(truncateText(asString(raw.code_owner, ""), 220)),
    rule_confidence: asOptionalNumber(raw.rule_confidence),
    rule_confidence_label: asOptionalString(asString(raw.rule_confidence_label, "")),
    git_diff_file_changed: raw.git_diff_file_changed === undefined ? undefined : Boolean(raw.git_diff_file_changed),
    git_diff_line_changed: raw.git_diff_line_changed === undefined ? undefined : Boolean(raw.git_diff_line_changed),
    dependency_reachability: normalizeDependencyReachability(raw.dependency_reachability),
    patch_preview: truncateText(asString(raw.patch_preview, ""), patchLimit),
    attack_scenario: asOptionalString(truncateText(asString(raw.attack_scenario, ""), textLimit)),
    exploitation_example: asOptionalString(truncateText(asString(raw.exploitation_example, ""), textLimit)),
    proof_of_concept: asOptionalString(truncateText(asString(raw.proof_of_concept, ""), pocLimit)),
    proof_of_concept_template: asOptionalString(truncateText(asString(raw.proof_of_concept_template, ""), pocLimit)),
    cve_ids: asArray(raw.cve_ids).map((item) => asString(item).toUpperCase()).filter(Boolean).slice(0, 20),
    advisory_ids: asArray(raw.advisory_ids).map((item) => asString(item).toUpperCase()).filter(Boolean).slice(0, 20),
    dependency_name: asOptionalString(truncateText(asString(raw.dependency_name, ""), 200)),
    dependency_version: asOptionalString(truncateText(asString(raw.dependency_version, ""), 120)),
    dependency_id: asOptionalString(truncateText(asString(raw.dependency_id, ""), 120)),
    known_exploited: raw.known_exploited === undefined ? undefined : Boolean(raw.known_exploited),
    exploit_maturity: asOptionalString(truncateText(asString(raw.exploit_maturity, ""), 120)),
    exploitability_context: asOptionalString(truncateText(asString(raw.exploitability_context, ""), textLimit)),
    release_gate_action: asOptionalString(truncateText(asString(raw.release_gate_action, ""), 80)),
    active_poc: normalizeActivePoc(raw.active_poc, pocLimit),
    fix_verification: normalizeFixVerification(raw.fix_verification, pocLimit),
    evidence_replay_pack: normalizeEvidenceReplayPack(raw.evidence_replay_pack, textLimit),
    rule_id: asString(raw.rule_id, "rule"),
    fix_artifact_kind:
      asString(raw.fix_artifact_kind, "").toLowerCase() === "exact_patch"
        ? "exact_patch"
        : asString(raw.fix_artifact_kind, "").toLowerCase() === "guidance"
          ? "guidance"
          : undefined,
    fix_artifact_label: asOptionalString(truncateText(asString(raw.fix_artifact_label, ""), 120)),
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
  const currentVulnSummary = report.vulnerability_fixed_code_report.summary;
  const currentExecSummary = report.executive_summary;
  const severityFromFindings = summarizeSeverity(findings);
  const severityFromSummary = normalizeSeverityDistribution(
    currentVulnSummary.severity_distribution,
    normalizeSeverityDistribution(currentExecSummary.severity_distribution),
  );
  const severityFromManagementBreakdown = summarizeSeverityBreakdownGroups(
    asRecord(currentExecSummary.management_summary).severity_breakdown_groups,
  );
  const severityDistribution =
    Object.values(severityFromFindings).some((value) => Number(value || 0) > 0)
      ? severityFromFindings
      : Object.values(severityFromSummary).some((value) => Number(value || 0) > 0)
        ? severityFromSummary
        : Object.values(severityFromManagementBreakdown).some((value) => Number(value || 0) > 0)
          ? severityFromManagementBreakdown
          : severityFromSummary;
  const filesImpacted = findings.length > 0
    ? new Set(findings.map((item) => item.file_path)).size
    : asNumber(currentVulnSummary.files_impacted, asNumber(currentExecSummary.total_files_impacted, 0));
  const reviewedSummaryFallback = asNumber((currentVulnSummary as Record<string, unknown>).reviewed_findings, asNumber((currentExecSummary as unknown as Record<string, unknown>).reviewed_findings, 0));
  const openSummaryFallback = asNumber((currentVulnSummary as Record<string, unknown>).open_findings, asNumber((currentExecSummary as unknown as Record<string, unknown>).open_findings, 0));
  const reviewed = findings.length > 0
    ? findings.filter((item) => item.status === "Reviewed").length
    : reviewedSummaryFallback;
  const open = findings.length > 0
    ? Math.max(0, findings.length - reviewed)
    : openSummaryFallback || Math.max(0, asNumber(currentVulnSummary.total_findings, asNumber(currentExecSummary.total_vulnerabilities, 0)) - reviewed);
  const totalFindings = findings.length > 0
    ? findings.length
    : asNumber(currentVulnSummary.total_findings, asNumber(currentExecSummary.total_vulnerabilities, 0));
  const rawTotal = Math.max(
    totalFindings,
    asNumber(currentVulnSummary.raw_findings_total, asNumber(currentExecSummary.total_vulnerabilities, totalFindings)),
  );
  const duplicateRemoved = asNumber(
    currentVulnSummary.duplicate_findings_removed,
    asNumber(currentExecSummary.duplicate_findings_removed, 0),
  );
  const activeRiskFindings = asNumber(
    currentVulnSummary.active_risk_findings,
    asNumber(currentExecSummary.active_risk_findings, (severityDistribution.Critical || 0) + (severityDistribution.High || 0)),
  );

  report.vulnerability_fixed_code_report.summary.total_findings = totalFindings;
  report.vulnerability_fixed_code_report.summary.raw_findings_total = rawTotal;
  report.vulnerability_fixed_code_report.summary.severity_distribution = severityDistribution;
  report.vulnerability_fixed_code_report.summary.files_impacted = filesImpacted;
  report.vulnerability_fixed_code_report.summary.active_risk_findings = activeRiskFindings;
  report.vulnerability_fixed_code_report.summary.open_findings = open;
  report.vulnerability_fixed_code_report.summary.reviewed_findings = reviewed;

  report.executive_summary.total_vulnerabilities = totalFindings;
  report.executive_summary.deduplicated_vulnerabilities = asNumber(
    report.executive_summary.deduplicated_vulnerabilities,
    totalFindings,
  );
  report.executive_summary.duplicate_findings_removed = duplicateRemoved;
  report.executive_summary.total_files_impacted = filesImpacted;
  report.executive_summary.severity_distribution = { ...severityDistribution };
  report.executive_summary.active_risk_findings = activeRiskFindings;
  const managementSummary = asRecord(report.executive_summary.management_summary);
  const existingManagementSeverity = normalizeSeverityDistribution(
    managementSummary.severity_distribution_raw || managementSummary.severity_distribution,
    severityDistribution,
  );
  const managementSeverity =
    Object.values(existingManagementSeverity).some((value) => Number(value || 0) > 0)
      ? existingManagementSeverity
      : severityDistribution;
  report.executive_summary.management_summary = {
    ...managementSummary,
    total_findings: asNumber(managementSummary.total_findings, totalFindings) || totalFindings,
    deduplicated_vulnerabilities: asNumber(managementSummary.deduplicated_vulnerabilities, totalFindings) || totalFindings,
    active_risk_findings:
      asNumber(managementSummary.active_risk_findings, activeRiskFindings) || activeRiskFindings,
    severity_distribution: managementSeverity,
    severity_distribution_raw: managementSeverity,
    severity_breakdown_groups: asArray(managementSummary.severity_breakdown_groups).length
      ? asArray(managementSummary.severity_breakdown_groups).map((item) => asRecord(item))
      : buildSeverityBreakdownGroups(findings),
    top_vulnerability_types: normalizeTopTypeRows(managementSummary.top_vulnerability_types).length
      ? normalizeTopTypeRows(managementSummary.top_vulnerability_types)
      : buildTopVulnerabilityTypeRows(findings),
    top_owasp_categories: normalizeTopOwaspRows(managementSummary.top_owasp_categories).length
      ? normalizeTopOwaspRows(managementSummary.top_owasp_categories)
      : buildTopOwaspRows(findings),
    affected_modules: normalizeAffectedModuleRows(managementSummary.affected_modules).length
      ? normalizeAffectedModuleRows(managementSummary.affected_modules)
      : buildAffectedModuleRows(findings),
    risk_score: asNumber(managementSummary.risk_score, currentExecSummary.risk_score || 0),
    risk_rating: asString(managementSummary.risk_rating, currentExecSummary.risk_rating || "Informational"),
  };
}

function buildFindingIdentity(finding: VulnerabilityFinding): string {
  if (finding.finding_uid && finding.finding_uid.trim().length > 0) {
    return finding.finding_uid;
  }
  const ruleId = finding.rule_id || "rule";
  return `${ruleId}::${finding.file_path}::${finding.line_number}`;
}

function normalizeRole(value: unknown): UserRole {
  return normalizeUserRole(value);
}

function normalizeScanPreset(value: unknown): ScanPreset {
  const candidate = asString(value, "standard").toLowerCase();
  if (candidate === "fast" || candidate === "standard" || candidate === "deep") {
    return candidate;
  }
  return "standard";
}

function normalizeCanonicalScan(
  input: unknown,
  fallback: {
    scanId: string;
    projectPath: string;
    requestedRole: UserRole;
    scanPreset: ScanPreset;
    startedAt: string;
    completedAt: string;
    report: UniversalScanReport;
  },
): CanonicalScanObject {
  const raw = asRecord(input);
  if (raw.schema_version === "codesentinelx.canonical_scan.v1") {
    const canonical = sanitizeUnknownValue(raw, 6) as CanonicalScanObject;
    canonical.scan_id = asString(canonical.scan_id, fallback.scanId);
    canonical.target_path = asString(canonical.target_path, fallback.projectPath);
    canonical.target_type =
      canonical.target_type === "file" || canonical.target_type === "folder" || canonical.target_type === "unknown"
        ? canonical.target_type
        : "unknown";
    canonical.requested_role = normalizeRole(canonical.requested_role);
    canonical.execution_role = normalizeRole(canonical.execution_role || "Admin");
    canonical.scan_preset = normalizeScanPreset(canonical.scan_preset);
    canonical.started_at = normalizeIso(canonical.started_at || fallback.startedAt);
    canonical.completed_at = normalizeIso(canonical.completed_at || fallback.completedAt);
    canonical.severity_distribution = normalizeSeverityDistribution(canonical.severity_distribution);
    return canonical;
  }
  return buildCanonicalScanObject(fallback);
}

function normalizeProjectionCache(input: unknown): Partial<Record<UserRole, RoleProjectionMetadata>> {
  const raw = asRecord(input);
  const cache: Partial<Record<UserRole, RoleProjectionMetadata>> = {};
  for (const role of USER_ROLE_SET) {
    const entry = asRecord(raw[role]);
    if (!Object.keys(entry).length) {
      continue;
    }
    cache[role] = {
      role,
      source_scan_id: asString(entry.source_scan_id, ""),
      source_schema_version: "codesentinelx.canonical_scan.v1",
      generated_at: normalizeIso(entry.generated_at),
      visibility:
        entry.visibility === "full" ||
        entry.visibility === "security" ||
        entry.visibility === "developer" ||
        entry.visibility === "redacted" ||
        entry.visibility === "summary"
          ? entry.visibility
          : "security",
      projection_reason: asString(entry.projection_reason, `Role projection derived from canonical scan ${asString(entry.source_scan_id, "")}; scanner was not invoked.`),
      inclusion_policy: asString(entry.inclusion_policy, "Projection includes fields permitted by the selected role policy."),
      redaction_policy: asString(entry.redaction_policy, "Projection redaction is controlled by the selected role policy."),
      allowed_sections: asArray(entry.allowed_sections).map((item) => asString(item)).filter(Boolean),
      redacted_fields: asArray(entry.redacted_fields).map((item) => asString(item)).filter(Boolean),
      scanner_invoked: false,
    };
  }
  return cache;
}

function refreshCanonicalScan(record: ScanRecord): void {
  record.canonicalScan = buildCanonicalScanObject({
    scanId: record.scanId,
    projectPath: record.projectPath,
    requestedRole: record.role,
    scanPreset: normalizeScanPreset(record.report.executive_summary.scan_preset),
    startedAt: record.startedAt,
    completedAt: record.completedAt,
    report: record.report,
  });
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
  const normalized = {
    Critical: asNumber(source.Critical, base.Critical || 0),
    High: asNumber(source.High, base.High || 0),
    Medium: asNumber(source.Medium, base.Medium || 0),
    Low: asNumber(source.Low, base.Low || 0),
    Info: asNumber(source.Info, base.Info || 0),
  };
  const normalizedTotal = Object.values(normalized).reduce((total, value) => total + Number(value || 0), 0);
  const fallbackTotal = Object.values(base).reduce((total, value) => total + Number(value || 0), 0);
  return normalizedTotal <= 0 && fallbackTotal > 0
    ? {
        Critical: Number(base.Critical || 0),
        High: Number(base.High || 0),
        Medium: Number(base.Medium || 0),
        Low: Number(base.Low || 0),
        Info: Number(base.Info || 0),
      }
    : normalized;
}

function summarizeSeverityBreakdownGroups(input: unknown): Record<Severity, number> {
  const summary: Record<Severity, number> = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };
  for (const section of asArray(input)) {
    const sectionRecord = asRecord(section);
    const severity = normalizeSeverity(sectionRecord.severity);
    if (!SEVERITY_SET.has(severity)) {
      continue;
    }
    for (const group of asArray(sectionRecord.groups)) {
      summary[severity] += asNumber(asRecord(group).count, 0);
    }
  }
  return summary;
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

function normalizeProfileCompliance(input: unknown): UniversalScanReport["profile_compliance"] | undefined {
  const raw = asRecord(input);
  if (!Object.keys(raw).length) {
    return undefined;
  }
  const frameworks = asArray(raw.frameworks)
    .map((entry) => {
      const framework = asRecord(entry);
      const rows = asArray(framework.rows)
        .map((rowInput, index) => {
          const row = asRecord(rowInput);
          const statusRaw = asString(row.status, "gap").toLowerCase();
          const status: "covered" | "gap" | "not_applicable" =
            statusRaw === "covered" ? "covered" : statusRaw === "not_applicable" ? "not_applicable" : "gap";
          const id = asString(row.id, asString(row.item_id, asString(row.key, `ITEM-${index + 1}`)));
          const title = asString(
            row.title,
            asString(row.category, asString(row.name, asString(row.description, "Uncategorized item"))),
          );
          const findingCount = asNumber(row.finding_count, asNumber(row.findings, 0));
          const controlCount = asNumber(row.control_count, asNumber(row.controls, 0));
          const total = asNumber(row.count, findingCount + controlCount);
          return {
            id,
            title,
            status,
            finding_count: findingCount,
            control_count: controlCount,
            count: total,
          };
        })
        .slice(0, 80);

      const summary = asRecord(framework.summary);
      return {
        framework_id: asString(framework.framework_id, asString(framework.id, "unknown-framework")),
        framework_name: asString(framework.framework_name, asString(framework.name, "Framework")),
        version: asString(framework.version, "N/A"),
        label: asString(framework.label, asString(framework.framework_name, "Framework")),
        prefix: asString(framework.prefix, ""),
        applicable: Boolean(framework.applicable),
        summary: {
          covered: asNumber(summary.covered, 0),
          gap: asNumber(summary.gap, 0),
          not_applicable: asNumber(summary.not_applicable, 0),
          mapped_findings: asNumber(summary.mapped_findings, 0),
          mapped_controls: asNumber(summary.mapped_controls, 0),
        },
        rows,
      };
    })
    .slice(0, 12);

  const versions = asRecord(raw.framework_versions);
  const summary = asRecord(raw.summary);
  const scanProfile: "codebase" = "codebase";

  return {
    scan_profile: scanProfile,
    scan_profile_label: asString(raw.scan_profile_label, "Codebase"),
    framework_versions: {
      owasp_top_10: asString(versions.owasp_top_10, "2021"),
      owasp_api_top_10: asString(versions.owasp_api_top_10, "2023"),
      asvs: asString(versions.asvs, "5.0.0"),
      wstg: asString(versions.wstg, "4.2"),
    },
    applicable_framework_ids: asArray(raw.applicable_framework_ids).map((item) => asString(item)).filter(Boolean).slice(0, 20),
    frameworks,
    summary: {
      frameworks_total: asNumber(summary.frameworks_total, frameworks.length),
      frameworks_applicable: asNumber(
        summary.frameworks_applicable,
        frameworks.filter((framework) => framework.applicable).length,
      ),
      items_covered: asNumber(summary.items_covered, 0),
      items_gap: asNumber(summary.items_gap, 0),
      items_not_applicable: asNumber(summary.items_not_applicable, 0),
      mapped_findings_total: asNumber(summary.mapped_findings_total, 0),
      mapped_controls_total: asNumber(summary.mapped_controls_total, 0),
    },
  };
}

function normalizeEnterpriseAssurance(input: unknown): EnterpriseAssuranceSummary | undefined {
  const raw = asRecord(input);
  if (!Object.keys(raw).length) {
    return undefined;
  }
  const statusRaw = asString(raw.status, "blocked").toLowerCase();
  const status: EnterpriseAssuranceSummary["status"] =
    statusRaw === "ready" ? "ready" : statusRaw === "warning" ? "warning" : "blocked";
  return {
    status,
    is_enterprise_ready: Boolean(raw.is_enterprise_ready),
    scan_profile: "codebase",
    required_tools: asArray(raw.required_tools).map((item) => asString(item)).filter(Boolean).slice(0, 40),
    required_tools_total: asNumber(raw.required_tools_total, 0),
    required_tools_ready: asNumber(raw.required_tools_ready, 0),
    required_tools_coverage_percent: asNumber(raw.required_tools_coverage_percent, 0),
    recommended_tools: asArray(raw.recommended_tools).map((item) => asString(item)).filter(Boolean).slice(0, 40),
    recommended_tools_total: asOptionalNumber(raw.recommended_tools_total),
    recommended_tools_ready: asOptionalNumber(raw.recommended_tools_ready),
    recommended_tools_coverage_percent: asOptionalNumber(raw.recommended_tools_coverage_percent),
    toolchain_success_rate_percent: asNumber(raw.toolchain_success_rate_percent, 0),
    toolchain_attempted_tools: asNumber(raw.toolchain_attempted_tools, 0),
    toolchain_failed_tools: asNumber(raw.toolchain_failed_tools, 0),
    toolchain_unavailable_tools: asNumber(raw.toolchain_unavailable_tools, 0),
    toolchain_no_runner_tools: asNumber(raw.toolchain_no_runner_tools, 0),
    readiness_score: asNumber(raw.readiness_score, 0),
    blockers: asArray(raw.blockers).map((item) => truncateText(asString(item), 500)).filter(Boolean).slice(0, 30),
    advisories: asArray(raw.advisories).map((item) => truncateText(asString(item), 500)).filter(Boolean).slice(0, 30),
    recommendation: truncateText(asString(raw.recommendation, ""), 1000),
  };
}

function normalizeToolchainExecutionSummary(input: unknown): ToolchainExecutionSummary | undefined {
  const raw = asRecord(input);
  if (!Object.keys(raw).length) {
    return undefined;
  }
  const failureRows = asArray(raw.failures)
    .map((item) => asRecord(item))
    .map((row) => ({
      tool: asString(row.tool, "unknown"),
      status: asString(row.status, "unknown"),
      message: truncateText(asString(row.message, ""), 500),
      errors: asArray(row.errors).map((error) => truncateText(asString(error), 500)).filter(Boolean).slice(0, 10),
    }))
    .slice(0, 40);
  const slowRows = asArray(raw.slowest_tools)
    .map((item) => asRecord(item))
    .map((row) => ({
      tool: asString(row.tool, "unknown"),
      duration_ms: asNumber(row.duration_ms, 0),
      findings_count: asNumber(row.findings_count, 0),
      status: asString(row.status, "unknown"),
    }))
    .slice(0, 30);
  return {
    total_tools: asNumber(raw.total_tools, 0),
    selected_tools: asNumber(raw.selected_tools, 0),
    available_tools: asNumber(raw.available_tools, 0),
    integrated_tools: asNumber(raw.integrated_tools, 0),
    runner_available_tools: asNumber(raw.runner_available_tools, 0),
    attempted_tools: asNumber(raw.attempted_tools, 0),
    successful_tools: asNumber(raw.successful_tools, 0),
    failed_tools: asNumber(raw.failed_tools, 0),
    unavailable_tools: asNumber(raw.unavailable_tools, 0),
    no_runner_tools: asNumber(raw.no_runner_tools, 0),
    skipped_tools: asNumber(raw.skipped_tools, 0),
    success_rate_percent: asNumber(raw.success_rate_percent, 0),
    status_distribution: normalizeCountMap(raw.status_distribution),
    failures: failureRows,
    slowest_tools: slowRows,
  };
}

function normalizeToolExecutionStatus(input: unknown): ToolExecutionStatus | undefined {
  const raw = asRecord(input);
  if (!Object.keys(raw).length) {
    return undefined;
  }
  return {
    attempted: Boolean(raw.attempted),
    status: asString(raw.status, "unknown"),
    duration_ms: asNumber(raw.duration_ms, 0),
    findings_count: asNumber(raw.findings_count, 0),
    errors: asArray(raw.errors).map((item) => truncateText(asString(item), 500)).filter(Boolean).slice(0, 12),
    evidence: normalizeToolExecutionEvidence(raw.evidence),
  };
}

function normalizeToolExecutionEvidence(input: unknown): ToolExecutionStatus["evidence"] {
  return asArray(input)
    .map((item) => asRecord(item))
    .map((row) => ({
      timestamp: asOptionalString(row.timestamp),
      command: asOptionalString(truncateText(asString(row.command, ""), 1200)),
      cwd: asOptionalString(truncateText(asString(row.cwd, ""), 500)),
      exit_code: asOptionalNumber(row.exit_code),
      duration_ms: asOptionalNumber(row.duration_ms),
      stdout_sha256: asOptionalString(asString(row.stdout_sha256, "")),
      stderr_sha256: asOptionalString(asString(row.stderr_sha256, "")),
      stdout_bytes: asOptionalNumber(row.stdout_bytes),
      stderr_bytes: asOptionalNumber(row.stderr_bytes),
      stdout_preview: asOptionalString(truncateText(asString(row.stdout_preview, ""), 1800)),
      stderr_preview: asOptionalString(truncateText(asString(row.stderr_preview, ""), 1800)),
    }))
    .slice(0, 8);
}

function normalizeActivePoc(input: unknown, maxLength: number): VulnerabilityFinding["active_poc"] | undefined {
  const raw = asRecord(input);
  if (!Object.keys(raw).length) {
    return undefined;
  }
  return {
    mode: asOptionalString(raw.mode),
    family: asOptionalString(raw.family),
    command: asOptionalString(truncateText(asString(raw.command, ""), maxLength)),
    status: asOptionalString(raw.status),
    executed: raw.executed === undefined ? undefined : Boolean(raw.executed),
    exit_code: raw.exit_code === null || raw.exit_code === undefined ? undefined : asNumber(raw.exit_code, 0),
    output: asOptionalString(truncateText(asString(raw.output, ""), maxLength)),
    line_tested: raw.line_tested === undefined ? undefined : asNumber(raw.line_tested, 0),
  };
}

function buildSeverityBreakdownGroups(findings: VulnerabilityFinding[]): Array<Record<string, unknown>> {
  const bySeverity = new Map<Severity, Map<string, {
    title: string;
    cwe: string;
    owasp: string;
    count: number;
    modules: Set<string>;
    instances: Array<Record<string, unknown>>;
  }>>();
  for (const finding of findings) {
    const severity = normalizeSeverity(finding.severity);
    const title = asString((finding as unknown as Record<string, unknown>).vulnerability_title, asString((finding as unknown as Record<string, unknown>).title, asString(finding.rule_id, "Security Issue")));
    const cwe = asString(finding.cwe_id, "N/A");
    const owasp = asString(finding.owasp_mapping, "N/A");
    const key = `${title.toLowerCase()}::${cwe.toLowerCase()}`;
    if (!bySeverity.has(severity)) {
      bySeverity.set(severity, new Map());
    }
    const severityMap = bySeverity.get(severity)!;
    if (!severityMap.has(key)) {
      severityMap.set(key, { title, cwe, owasp, count: 0, modules: new Set(), instances: [] });
    }
    const group = severityMap.get(key)!;
    const filePath = asString(finding.file_path, "unknown");
    const lineNumber = asNumber(finding.line_number, 1);
    const module = moduleFromPath(filePath);
    group.count += 1;
    group.modules.add(module);
    group.instances.push({
      file_name: fileNameFromPath(filePath),
      file_path: filePath,
      line_number: lineNumber,
      location: `${filePath}:${lineNumber}`,
      module,
    });
  }
  return SEVERITY_VALUES.map((severity) => {
    const groups = Array.from(bySeverity.get(severity)?.values() || [])
      .sort((left, right) => right.count - left.count || left.title.localeCompare(right.title))
      .map((group) => ({
        title: group.title,
        vulnerability: group.title,
        cwe: group.cwe,
        cwe_id: group.cwe,
        owasp: group.owasp,
        owasp_mapping: group.owasp,
        count: group.count,
        group_count: group.count,
        modules: Array.from(group.modules).sort(),
        instances: group.instances,
      }));
    return {
      severity,
      count: groups.reduce((total, group) => total + Number(group.count || 0), 0),
      group_count: groups.length,
      groups,
    };
  }).filter((section) => section.groups.length > 0);
}

function buildTopVulnerabilityTypeRows(findings: VulnerabilityFinding[]): Array<{ type: string; count: number }> {
  const counts: Record<string, number> = {};
  for (const finding of findings) {
    const title = asString((finding as unknown as Record<string, unknown>).vulnerability_title, asString((finding as unknown as Record<string, unknown>).title, asString(finding.rule_id, "Security Issue")));
    counts[title] = (counts[title] || 0) + 1;
  }
  return sortCountRows(counts).map(([type, count]) => ({ type, count }));
}

function buildTopOwaspRows(findings: VulnerabilityFinding[]): Array<{ owasp_category: string; count: number }> {
  const counts: Record<string, number> = {};
  for (const finding of findings) {
    const owasp = asString(finding.owasp_mapping, "");
    if (owasp && owasp !== "N/A") {
      counts[owasp] = (counts[owasp] || 0) + 1;
    }
  }
  return sortCountRows(counts).map(([owasp_category, count]) => ({ owasp_category, count }));
}

function buildAffectedModuleRows(findings: VulnerabilityFinding[]): Array<{ module: string; count: number; critical: number; high: number }> {
  const rows = new Map<string, { module: string; count: number; critical: number; high: number }>();
  for (const finding of findings) {
    const module = moduleFromPath(finding.file_path);
    if (!rows.has(module)) {
      rows.set(module, { module, count: 0, critical: 0, high: 0 });
    }
    const row = rows.get(module)!;
    row.count += 1;
    if (finding.severity === "Critical") row.critical += 1;
    if (finding.severity === "High") row.high += 1;
  }
  return Array.from(rows.values()).sort((left, right) => right.count - left.count || left.module.localeCompare(right.module)).slice(0, 40);
}

function sortCountRows(counts: Record<string, number>): Array<[string, number]> {
  return Object.entries(counts)
    .filter(([key, count]) => key && key !== "N/A" && Number(count || 0) > 0)
    .sort((left, right) => right[1] - left[1] || left[0].localeCompare(right[0]))
    .slice(0, 20);
}

function moduleFromPath(value: unknown): string {
  const normalized = asString(value, "root").replaceAll("\\", "/");
  const parts = normalized.split("/").filter(Boolean);
  return parts[0] || "root";
}

function fileNameFromPath(value: unknown): string {
  const normalized = asString(value, "unknown").replaceAll("\\", "/");
  const parts = normalized.split("/").filter(Boolean);
  return parts[parts.length - 1] || "unknown";
}

function normalizeCommandExecution(
  input: unknown,
  maxLength: number,
):
  | {
      command?: string;
      status?: string;
      exit_code?: number | null;
      output?: string;
    }
  | undefined {
  const raw = asRecord(input);
  if (!Object.keys(raw).length) {
    return undefined;
  }
  return {
    command: asOptionalString(truncateText(asString(raw.command, ""), maxLength)),
    status: asOptionalString(asString(raw.status, "")),
    exit_code: raw.exit_code === null || raw.exit_code === undefined ? undefined : asNumber(raw.exit_code, 0),
    output: asOptionalString(truncateText(asString(raw.output, ""), maxLength)),
  };
}

function normalizeFixVerification(input: unknown, maxLength: number): VulnerabilityFinding["fix_verification"] | undefined {
  const raw = asRecord(input);
  if (!Object.keys(raw).length) {
    return undefined;
  }
  return {
    performed: raw.performed === undefined ? undefined : Boolean(raw.performed),
    result: asOptionalString(asString(raw.result, "")),
    reason: asOptionalString(truncateText(asString(raw.reason, ""), maxLength)),
    pre_fix_status: asOptionalString(asString(raw.pre_fix_status, "")),
    post_fix_status: asOptionalString(asString(raw.post_fix_status, "")),
    post_fix_execution: normalizeCommandExecution(raw.post_fix_execution, maxLength),
    build_verification: normalizeCommandExecution(raw.build_verification, maxLength),
    test_verification: normalizeCommandExecution(raw.test_verification, maxLength),
  };
}

function normalizeActivePocSummary(input: unknown): { executed: number; passed: number; failed: number; skipped: number } | undefined {
  const raw = asRecord(input);
  if (!Object.keys(raw).length) {
    return undefined;
  }
  const passed = asNumber(raw.passed, asNumber(raw.verified, 0));
  const failed = asNumber(raw.failed, asNumber(raw.inconclusive, 0));
  return {
    executed: asNumber(raw.executed, 0),
    passed,
    failed,
    skipped: asNumber(raw.skipped, 0),
  };
}

function normalizeEvidenceReplayPack(
  input: unknown,
  maxLength: number,
): VulnerabilityFinding["evidence_replay_pack"] | undefined {
  const raw = asRecord(input);
  if (!Object.keys(raw).length) {
    return undefined;
  }
  const envRaw = asRecord(raw.env_fingerprint);
  const outputHashesRaw = asRecord(raw.output_hashes);
  const outputSizesRaw = asRecord(raw.output_sizes);
  const replayScriptRaw = asRecord(raw.replay_script);
  return {
    enabled: raw.enabled === undefined ? undefined : Boolean(raw.enabled),
    mode: asOptionalString(asString(raw.mode, "")),
    inferred_tool: asOptionalString(asString(raw.inferred_tool, "")),
    recorded: raw.recorded === undefined ? undefined : Boolean(raw.recorded),
    env_fingerprint: {
      os: asOptionalString(asString(envRaw.os, "")),
      os_release: asOptionalString(asString(envRaw.os_release, "")),
      platform: asOptionalString(asString(envRaw.platform, "")),
      architecture: asOptionalString(asString(envRaw.architecture, "")),
      python_version: asOptionalString(asString(envRaw.python_version, "")),
    },
    replay_id: asOptionalString(asString(raw.replay_id, "")),
    timestamp: asOptionalString(asString(raw.timestamp, "")),
    tool: asOptionalString(asString(raw.tool, "")),
    command: asOptionalString(truncateText(asString(raw.command, ""), maxLength)),
    cwd: asOptionalString(truncateText(asString(raw.cwd, ""), 500)),
    exit_code: raw.exit_code === null || raw.exit_code === undefined ? undefined : asNumber(raw.exit_code, 0),
    duration_ms: asOptionalNumber(raw.duration_ms),
    output_hashes: {
      stdout_sha256: asOptionalString(asString(outputHashesRaw.stdout_sha256, "")),
      stderr_sha256: asOptionalString(asString(outputHashesRaw.stderr_sha256, "")),
    },
    output_sizes: {
      stdout_bytes: asOptionalNumber(outputSizesRaw.stdout_bytes),
      stderr_bytes: asOptionalNumber(outputSizesRaw.stderr_bytes),
    },
    record_sha256: asOptionalString(asString(raw.record_sha256, "")),
    replay_script: {
      windows_ps1: asOptionalString(truncateText(asString(replayScriptRaw.windows_ps1, ""), 1800)),
      posix_sh: asOptionalString(truncateText(asString(replayScriptRaw.posix_sh, ""), 1800)),
    },
    reason: asOptionalString(truncateText(asString(raw.reason, ""), 600)),
  };
}

function normalizeDeterministicReplay(input: unknown):
  | {
      enabled: boolean;
      mode: string;
      findings_total: number;
      findings_with_replay: number;
      findings_without_replay: number;
      replay_coverage_percent: number;
      tool_evidence_records: number;
      tools_with_evidence: string[];
      tool_mismatch_counts: Record<string, number>;
      env_fingerprint: Record<string, unknown>;
      record_hashes: string[];
    }
  | undefined {
  const raw = asRecord(input);
  if (!Object.keys(raw).length) {
    return undefined;
  }
  return {
    enabled: Boolean(raw.enabled),
    mode: asString(raw.mode, "deterministic-evidence-replay"),
    findings_total: asNumber(raw.findings_total, 0),
    findings_with_replay: asNumber(raw.findings_with_replay, 0),
    findings_without_replay: asNumber(raw.findings_without_replay, 0),
    replay_coverage_percent: asNumber(raw.replay_coverage_percent, 0),
    tool_evidence_records: asNumber(raw.tool_evidence_records, 0),
    tools_with_evidence: asArray(raw.tools_with_evidence).map((item) => asString(item)).filter(Boolean).slice(0, 80),
    tool_mismatch_counts: normalizeCountMap(raw.tool_mismatch_counts),
    env_fingerprint: (sanitizeUnknownValue(raw.env_fingerprint, 2) as Record<string, unknown>) || {},
    record_hashes: asArray(raw.record_hashes)
      .map((item) => asString(item))
      .filter(Boolean)
      .slice(0, 300),
  };
}

function normalizeReportIntegrityChain(input: unknown):
  | {
      chain_version: string;
      tamper_evident: boolean;
      generated_at: string;
      metadata_sha256: string;
      findings_sha256: string;
      tool_evidence_sha256: string;
      report_sha256: string;
      previous_report_sha256?: string | null;
      chain_note?: string;
    }
  | undefined {
  const raw = asRecord(input);
  if (!Object.keys(raw).length) {
    return undefined;
  }
  return {
    chain_version: asString(raw.chain_version, "1.0"),
    tamper_evident: Boolean(raw.tamper_evident),
    generated_at: asString(raw.generated_at, ""),
    metadata_sha256: asString(raw.metadata_sha256, ""),
    findings_sha256: asString(raw.findings_sha256, ""),
    tool_evidence_sha256: asString(raw.tool_evidence_sha256, ""),
    report_sha256: asString(raw.report_sha256, ""),
    previous_report_sha256:
      raw.previous_report_sha256 === undefined ? undefined : (raw.previous_report_sha256 === null ? null : asString(raw.previous_report_sha256, "")),
    chain_note: asOptionalString(truncateText(asString(raw.chain_note, ""), 600)),
  };
}

function normalizeRiskIntelligence(input: unknown):
  | {
      findings_with_cve: number;
      findings_cvss_ge_7: number;
      known_exploited_findings: number;
    }
  | undefined {
  const raw = asRecord(input);
  if (!Object.keys(raw).length) {
    return undefined;
  }
  return {
    findings_with_cve: asNumber(raw.findings_with_cve, 0),
    findings_cvss_ge_7: asNumber(raw.findings_cvss_ge_7, 0),
    known_exploited_findings: asNumber(raw.known_exploited_findings, 0),
  };
}

function normalizeGitDiffTracking(input: unknown):
  | {
      enabled: boolean;
      changed_files: number;
      changed_lines: number;
      findings_on_changed_files: number;
      findings_on_changed_lines: number;
    }
  | undefined {
  const raw = asRecord(input);
  if (!Object.keys(raw).length) {
    return undefined;
  }
  return {
    enabled: Boolean(raw.enabled),
    changed_files: asNumber(raw.changed_files, 0),
    changed_lines: asNumber(raw.changed_lines, 0),
    findings_on_changed_files: asNumber(raw.findings_on_changed_files, 0),
    findings_on_changed_lines: asNumber(raw.findings_on_changed_lines, 0),
  };
}

function normalizeAffectedFileRows(
  input: unknown,
): Array<{ file: string; folder: string; count: number; critical: number; high: number }> {
  return asArray(input)
    .map((item) => {
      const row = asRecord(item);
      return {
        file: asString(row.file, "unknown"),
        folder: asString(row.folder, "."),
        count: asNumber(row.count, 0),
        critical: asNumber(row.critical, 0),
        high: asNumber(row.high, 0),
      };
    })
    .filter((row) => row.file)
    .slice(0, 120);
}

function normalizeAffectedFolderRows(
  input: unknown,
): Array<{ folder: string; count: number; critical: number; high: number }> {
  return asArray(input)
    .map((item) => {
      const row = asRecord(item);
      return {
        folder: asString(row.folder, "."),
        count: asNumber(row.count, 0),
        critical: asNumber(row.critical, 0),
        high: asNumber(row.high, 0),
      };
    })
    .filter((row) => row.folder)
    .slice(0, 120);
}

function normalizeAuthAbuseSessionSecurity(input: unknown):
  | {
      total_findings: number;
      severity_distribution: Record<string, number>;
      top_vulnerability_types: Array<{ type: string; count: number }>;
      affected_modules: Array<{ module: string; count: number; critical: number; high: number }>;
      affected_files: Array<{ file: string; folder: string; count: number; critical: number; high: number }>;
      issue_file_mapping?: Array<{ issue_type: string; file: string; folder: string; count: number; critical: number; high: number }>;
    }
  | undefined {
  const raw = asRecord(input);
  if (!Object.keys(raw).length) {
    return undefined;
  }
  return {
    total_findings: asNumber(raw.total_findings, 0),
    severity_distribution: normalizeSeverityDistribution(raw.severity_distribution),
    top_vulnerability_types: normalizeTopTypeRows(raw.top_vulnerability_types),
    affected_modules: normalizeAffectedModuleRows(raw.affected_modules),
    affected_files: normalizeAffectedFileRows(raw.affected_files),
    issue_file_mapping: asArray(raw.issue_file_mapping)
      .map((item) => {
        const row = asRecord(item);
        return {
          issue_type: asString(row.issue_type, "Issue"),
          file: asString(row.file, "unknown"),
          folder: asString(row.folder, "."),
          count: asNumber(row.count, 0),
          critical: asNumber(row.critical, 0),
          high: asNumber(row.high, 0),
        };
      })
      .filter((row) => row.issue_type && row.file)
      .slice(0, 120),
  };
}

function normalizeFalsePositiveReport(input: unknown): FalsePositiveReport | undefined {
  const raw = asRecord(input);
  if (!Object.keys(raw).length) {
    return undefined;
  }
  const candidates = asArray(raw.candidates)
    .map((item) => asRecord(item))
    .map((row) => ({
      finding_uid: asOptionalString(row.finding_uid),
      vulnerability_title: asOptionalString(row.vulnerability_title),
      severity: asOptionalString(row.severity) as Severity | undefined,
      file_path: asOptionalString(row.file_path),
      line_number: asOptionalNumber(row.line_number),
      reason_summary: asOptionalString(truncateText(asString(row.reason_summary, ""), 500)),
      reason_detail: asOptionalString(truncateText(asString(row.reason_detail, ""), 1200)),
      confidence: asOptionalNumber(row.confidence),
      verification_steps: asArray(row.verification_steps)
        .map((step) => truncateText(asString(step), 500))
        .filter(Boolean)
        .slice(0, 8),
    }))
    .slice(0, 120);

  return {
    policy_note: asOptionalString(truncateText(asString(raw.policy_note, ""), 2000)),
    candidate_count: asOptionalNumber(raw.candidate_count),
    candidates,
  };
}

function normalizeDependencyReachability(input: unknown):
  | {
      status: string;
      score: number;
      priority_factor?: number;
      package_candidates?: string[];
      import_evidence?: string[];
      manifest_present?: boolean;
      lockfile_present?: boolean;
      manifest_paths?: string[];
      lockfile_paths?: string[];
      declared_versions?: string[];
      locked_versions?: string[];
      advisory_ids?: string[];
      advisory_verified?: boolean;
      reasoning?: string;
    }
  | undefined {
  const raw = asRecord(input);
  if (!Object.keys(raw).length) {
    return undefined;
  }
  return {
    status: asString(raw.status, "unknown"),
    score: asNumber(raw.score, 1),
    priority_factor: asOptionalNumber(raw.priority_factor),
    package_candidates: asArray(raw.package_candidates).map((item) => asString(item)).filter(Boolean).slice(0, 8),
    import_evidence: asArray(raw.import_evidence).map((item) => asString(item)).filter(Boolean).slice(0, 8),
    manifest_present: raw.manifest_present === undefined ? undefined : Boolean(raw.manifest_present),
    lockfile_present: raw.lockfile_present === undefined ? undefined : Boolean(raw.lockfile_present),
    manifest_paths: asArray(raw.manifest_paths).map((item) => asString(item)).filter(Boolean).slice(0, 8),
    lockfile_paths: asArray(raw.lockfile_paths).map((item) => asString(item)).filter(Boolean).slice(0, 8),
    declared_versions: asArray(raw.declared_versions).map((item) => asString(item)).filter(Boolean).slice(0, 8),
    locked_versions: asArray(raw.locked_versions).map((item) => asString(item)).filter(Boolean).slice(0, 8),
    advisory_ids: asArray(raw.advisory_ids).map((item) => asString(item).toUpperCase()).filter(Boolean).slice(0, 12),
    advisory_verified: raw.advisory_verified === undefined ? undefined : Boolean(raw.advisory_verified),
    reasoning: asOptionalString(truncateText(asString(raw.reasoning, ""), 600)),
  };
}

function normalizeRoleAwareReport(input: unknown): RoleAwareReport | undefined {
  const raw = asRecord(input);
  if (!Object.keys(raw).length) {
    return undefined;
  }
  return {
    metadata: sanitizeUnknownValue(raw.metadata, 3) as Record<string, unknown>,
    visualization_hints: sanitizeUnknownValue(raw.visualization_hints, 3) as Record<string, unknown>,
    cto_board_view: sanitizeUnknownValue(raw.cto_board_view, 4) as Record<string, unknown>,
    ciso_security_view: sanitizeUnknownValue(raw.ciso_security_view, 4) as Record<string, unknown>,
    developer_devops_view: sanitizeUnknownValue(raw.developer_devops_view, 4) as Record<string, unknown>,
    risk_story_mode: sanitizeUnknownValue(raw.risk_story_mode, 4) as Record<string, unknown>,
    advanced_features: sanitizeUnknownValue(raw.advanced_features, 4) as Record<string, unknown>,
    enterprise_assurance: normalizeEnterpriseAssurance(raw.enterprise_assurance),
    false_positive_report: normalizeFalsePositiveReport(raw.false_positive_report),
  };
}

function buildPortfolioSummary(scans: ScanRecord[]): PortfolioSummary {
  if (scans.length === 0) {
    return {
      scansTotal: 0,
      repositoriesTotal: 0,
      trendDirection: "unavailable",
      trendDelta: 0,
      hotModules: [],
      recurringCwe: [],
      fixVelocityPercent: 0,
      suppressionDriftScore: 0,
    };
  }

  const uniqueRepos = new Set(scans.map((scan) => scan.projectPath));
  const moduleCounts = new Map<string, number>();
  const cweCounts = new Map<string, number>();
  let totalFindings = 0;
  let totalReviewed = 0;
  let totalDrift = 0;

  for (const scan of scans) {
    const summary = scan.report.vulnerability_fixed_code_report.summary;
    const findings = scan.report.vulnerability_fixed_code_report.findings || [];
    totalFindings += summary.total_findings || findings.length;
    totalReviewed += summary.reviewed_findings || 0;

    const suppressionReport = asRecord((scan.report as LooseRecord).suppression_report);
    totalDrift += asNumber(suppressionReport.suppression_drift_score, 0);

    for (const moduleRow of summary.affected_modules || []) {
      const current = moduleCounts.get(moduleRow.module) || 0;
      moduleCounts.set(moduleRow.module, current + moduleRow.count);
    }

    for (const finding of findings) {
      const cwe = asString((finding as unknown as LooseRecord).cwe_id, "").trim();
      if (!cwe || cwe.toUpperCase() === "N/A") {
        continue;
      }
      cweCounts.set(cwe, (cweCounts.get(cwe) || 0) + 1);
    }
  }

  const latest = scans[0];
  const previousSameProject = scans.find(
    (item, index) => index > 0 && item.projectPath === latest.projectPath,
  );
  const latestRisk = latest?.report.executive_summary.risk_score || 0;
  const previousRisk = previousSameProject?.report.executive_summary.risk_score;
  let trendDirection: PortfolioSummary["trendDirection"] = "unavailable";
  let trendDelta = 0;
  if (typeof previousRisk === "number") {
    trendDelta = Number((latestRisk - previousRisk).toFixed(2));
    if (trendDelta >= 1) {
      trendDirection = "declining";
    } else if (trendDelta <= -1) {
      trendDirection = "improving";
    } else {
      trendDirection = "stable";
    }
  }

  const hotModules = [...moduleCounts.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 8)
    .map(([module, count]) => ({ module, count }));
  const recurringCwe = [...cweCounts.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 8)
    .map(([cwe, count]) => ({ cwe, count }));

  return {
    scansTotal: scans.length,
    repositoriesTotal: uniqueRepos.size,
    trendDirection,
    trendDelta,
    hotModules,
    recurringCwe,
    fixVelocityPercent: Number(((totalReviewed / Math.max(1, totalFindings)) * 100).toFixed(2)),
    suppressionDriftScore: Number((totalDrift / Math.max(1, scans.length)).toFixed(2)),
  };
}

function normalizeCountMap(input: unknown): Record<string, number> {
  const source = asRecord(input);
  const result: Record<string, number> = {};
  for (const [key, value] of Object.entries(source)) {
    result[String(key)] = asNumber(value, 0);
  }
  return result;
}

function normalizeCompactObject(input: unknown): Record<string, unknown> | undefined {
  if (!isPlainObject(input)) {
    return undefined;
  }
  const sanitized = sanitizeUnknownValue(input, 2);
  if (!isPlainObject(sanitized)) {
    return undefined;
  }
  return sanitized as Record<string, unknown>;
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
