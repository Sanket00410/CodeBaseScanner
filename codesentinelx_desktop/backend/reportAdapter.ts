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
  const clone = cloneStructured(report);
  if (!clone) {
    return report;
  }

  const findings = (clone.vulnerability_fixed_code_report.findings || []).map((finding) => ({ ...finding }));

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

  clone.vulnerability_fixed_code_report.findings = findings;
  clone.vulnerability_fixed_code_report.summary.reviewed_findings = reviewed;
  clone.vulnerability_fixed_code_report.summary.open_findings = Math.max(0, findings.length - reviewed);
  clone.profile_compliance =
    clone.profile_compliance || clone.existing_implementation_report.profile_compliance || report.profile_compliance;
  return clone;
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

function cloneStructured<T>(payload: T | undefined): T | undefined {
  if (payload === undefined) {
    return undefined;
  }
  return JSON.parse(JSON.stringify(payload)) as T;
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
  const summary = record.report.vulnerability_fixed_code_report.summary;
  const suppressionReport =
    (record.report.vulnerability_fixed_code_report as { suppression_report?: { suppressed_count?: number } }).suppression_report ||
    (record.report as { suppression_report?: { suppressed_count?: number } }).suppression_report ||
    {};
  return {
    scanId: record.scanId,
    projectPath: record.projectPath,
    startedAt: record.startedAt,
    completedAt: record.completedAt,
    risk: record.report.executive_summary.risk_rating,
    riskScore: record.report.executive_summary.risk_score,
    totalFindings: summary.total_findings,
    reviewedFindings: summary.reviewed_findings || 0,
    suppressedCount: Number(suppressionReport.suppressed_count || 0),
    topModule: (summary.affected_modules || [])[0]?.module || "",
  };
}
