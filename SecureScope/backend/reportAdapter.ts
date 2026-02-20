import {
  FindingReviewState,
  ScanHistoryItem,
  ScanRecord,
  ScanView,
  UniversalScanReport,
  VulnerabilityFinding,
} from "./types";

export function findingIdentity(finding: VulnerabilityFinding): string {
  if (finding.finding_uid && finding.finding_uid.trim().length > 0) {
    return finding.finding_uid;
  }
  const ruleId = finding.rule_id || "rule";
  return `${ruleId}::${finding.file_path}::${finding.line_number}`;
}

export function applyFindingState(
  report: UniversalScanReport,
  states: Record<string, FindingReviewState>,
): UniversalScanReport {
  const findings = (report.vulnerability_fixed_code_report.findings || []).map((finding) => ({ ...finding }));

  let reviewed = 0;
  for (const finding of findings) {
    const id = findingIdentity(finding);
    finding.finding_uid = id;
    const state = states[id];
    if (state?.status === "Reviewed") {
      finding.status = "Reviewed";
      finding.reviewed_by = state.reviewedBy;
      finding.reviewed_at = state.reviewedAt;
      reviewed += 1;
    } else {
      finding.status = "Open";
      delete finding.reviewed_by;
      delete finding.reviewed_at;
    }
  }

  return {
    ...report,
    scanner: { ...report.scanner },
    executive_summary: {
      ...report.executive_summary,
      severity_distribution: { ...(report.executive_summary.severity_distribution || {}) },
      top_vulnerability_types: [...(report.executive_summary.top_vulnerability_types || [])],
      top_owasp_categories: [...(report.executive_summary.top_owasp_categories || [])],
      affected_modules: [...(report.executive_summary.affected_modules || [])],
      recommended_action_plan: [...(report.executive_summary.recommended_action_plan || [])],
    },
    existing_implementation_report: {
      ...report.existing_implementation_report,
      summary: {
        ...report.existing_implementation_report.summary,
        category_distribution: { ...(report.existing_implementation_report.summary.category_distribution || {}) },
        coverage_levels: { ...(report.existing_implementation_report.summary.coverage_levels || {}) },
        standards_coverage: { ...(report.existing_implementation_report.summary.standards_coverage || {}) },
      },
      controls: [...(report.existing_implementation_report.controls || [])],
      compliance_matrix: [...(report.existing_implementation_report.compliance_matrix || [])],
      profile_compliance: cloneProfileCompliance(report.existing_implementation_report.profile_compliance),
    },
    vulnerability_fixed_code_report: {
      ...report.vulnerability_fixed_code_report,
      summary: {
        ...report.vulnerability_fixed_code_report.summary,
        severity_distribution: { ...(report.vulnerability_fixed_code_report.summary.severity_distribution || {}) },
        top_vulnerability_types: [...(report.vulnerability_fixed_code_report.summary.top_vulnerability_types || [])],
        top_owasp_categories: [...(report.vulnerability_fixed_code_report.summary.top_owasp_categories || [])],
        affected_modules: [...(report.vulnerability_fixed_code_report.summary.affected_modules || [])],
        reviewed_findings: reviewed,
        open_findings: Math.max(0, findings.length - reviewed),
      },
      findings,
      auto_fix_recommendations: [...(report.vulnerability_fixed_code_report.auto_fix_recommendations || [])],
      toolchain_status: { ...(report.vulnerability_fixed_code_report.toolchain_status || {}) },
    },
    profile_compliance: cloneProfileCompliance(report.profile_compliance || report.existing_implementation_report.profile_compliance),
  };
}

function cloneProfileCompliance(
  profile:
    | UniversalScanReport["existing_implementation_report"]["profile_compliance"]
    | UniversalScanReport["profile_compliance"]
    | undefined,
) {
  if (!profile) {
    return undefined;
  }
  return JSON.parse(JSON.stringify(profile));
}

export function toScanView(record: ScanRecord): ScanView {
  return {
    scanId: record.scanId,
    projectPath: record.projectPath,
    requestedBy: record.requestedBy,
    role: record.role,
    startedAt: record.startedAt,
    completedAt: record.completedAt,
    report: applyFindingState(record.report, record.findingStates),
  };
}

export function toHistoryItem(record: ScanRecord): ScanHistoryItem {
  return {
    scanId: record.scanId,
    projectPath: record.projectPath,
    startedAt: record.startedAt,
    completedAt: record.completedAt,
    risk: record.report.executive_summary.risk_rating,
    totalFindings: record.report.vulnerability_fixed_code_report.summary.total_findings,
  };
}
