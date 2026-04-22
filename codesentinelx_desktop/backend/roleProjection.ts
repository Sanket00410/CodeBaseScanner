import {
  CanonicalScanObject,
  RoleProjectionMetadata,
  ScanPreset,
  ScanView,
  Severity,
  ToolchainStatusEntry,
  UserRole,
  UniversalScanReport,
  VulnerabilityFinding,
} from "./types";

const SEVERITIES: Severity[] = ["Critical", "High", "Medium", "Low", "Info"];

const ROLE_SECTION_RULES: Record<
  UserRole,
  {
    visibility: RoleProjectionMetadata["visibility"];
    sections: string[];
    redacted: string[];
    inclusionPolicy: string;
    redactionPolicy: string;
  }
> = {
  Admin: {
    visibility: "full",
    sections: ["all"],
    redacted: [],
    inclusionPolicy: "Admin projection includes the complete canonical scan for full-scope operational review.",
    redactionPolicy: "No presentation redaction is applied for Admin.",
  },
  "Security Analyst": {
    visibility: "security",
    sections: ["ciso_security_view", "risk_story_mode", "advanced_features", "enterprise_assurance", "false_positive_report", "data_quality", "tool_evidence"],
    redacted: [],
    inclusionPolicy: "Security Analyst projection includes broad security triage, evidence, prioritization, and validation context from the canonical scan.",
    redactionPolicy: "No presentation redaction is applied for Security Analyst.",
  },
  Developer: {
    visibility: "developer",
    sections: ["developer_devops_view", "risk_story_mode", "advanced_features", "fix_verification", "active_poc", "deterministic_replay"],
    redacted: [],
    inclusionPolicy: "Developer projection includes fix-oriented issue detail, file/line evidence, verification context, and remediation guidance from the canonical scan.",
    redactionPolicy: "No presentation redaction is applied for Developer remediation scope.",
  },
  Auditor: {
    visibility: "redacted",
    sections: ["enterprise_assurance", "false_positive_report", "data_quality", "deterministic_replay", "report_integrity_chain"],
    redacted: ["original_code", "fixed_code", "patch_preview", "proof_of_concept", "active_poc.output", "fix_verification.outputs"],
    inclusionPolicy: "Auditor projection includes traceable assurance, control, data-quality, replay, and integrity evidence from the canonical scan.",
    redactionPolicy: "Auditor projection redacts source code, patch content, proof-of-concept material, and command outputs while preserving traceability.",
  },
  Management: {
    visibility: "summary",
    sections: ["cto_board_view", "risk_story_mode", "enterprise_assurance", "management_summary", "severity_breakdown_groups"],
    redacted: ["findings", "raw_evidence", "source_code", "proof_of_concept", "tool_stdout", "tool_stderr"],
    inclusionPolicy: "Management projection includes executive counts, severity distribution, top issue types, OWASP categories, modules, and risk charts from the canonical scan.",
    redactionPolicy: "Management projection hides raw finding rows and technical evidence while preserving aggregate risk and drill-down group counts.",
  },
};

export function normalizeUserRole(value: unknown): UserRole {
  const label = String(value || "").trim().toLowerCase();
  switch (label) {
    case "admin":
    case "administrator":
      return "Admin";
    case "developer":
      return "Developer";
    case "auditor":
      return "Auditor";
    case "management":
    case "manager":
    case "board":
      return "Management";
    case "security analyst":
    case "securityanalyst":
    default:
      return "Security Analyst";
  }
}

export function inferTargetType(targetPath: string): CanonicalScanObject["target_type"] {
  if (!targetPath || targetPath === "unknown") {
    return "unknown";
  }
  return /\.[a-z0-9]{1,12}$/i.test(targetPath) ? "file" : "folder";
}

export function buildCanonicalScanObject(input: {
  scanId: string;
  projectPath: string;
  requestedRole: UserRole;
  scanPreset: ScanPreset;
  startedAt: string;
  completedAt: string;
  report: UniversalScanReport;
}): CanonicalScanObject {
  const report = input.report;
  const vulnerability = report.vulnerability_fixed_code_report;
  const summary = vulnerability.summary;
  const executive = report.executive_summary;
  const findings = cloneStructured(vulnerability.findings || []);
  const derivedTopTypes = buildTopVulnerabilityTypes(findings);
  const derivedTopOwasp = buildTopOwaspCategories(findings);
  const derivedModules = buildAffectedModules(findings);
  const severityDistribution = normalizeSeverityDistribution(
    summary.severity_distribution,
    normalizeSeverityDistribution(executive.severity_distribution, summarizeSeverity(findings)),
  );

  return {
    schema_version: "codesentinelx.canonical_scan.v1",
    scan_id: input.scanId,
    target_path: input.projectPath,
    target_type: inferTargetType(input.projectPath),
    requested_role: normalizeUserRole(input.requestedRole),
    execution_role: "Admin",
    scan_preset: input.scanPreset,
    started_at: input.startedAt,
    completed_at: input.completedAt,
    tool_execution_status: cloneStructured(vulnerability.toolchain_status || {}) as Record<string, ToolchainStatusEntry>,
    raw_findings: findings,
    deduplicated_findings: findings,
    severity_distribution: severityDistribution,
    cwe_owasp_cve_data: buildTaxonomyCounts(findings),
    evidence: {
      toolchain_execution: summary.toolchain_execution,
      deterministic_replay: summary.deterministic_replay || vulnerability.deterministic_replay,
      report_integrity_chain: summary.report_integrity_chain || vulnerability.report_integrity_chain,
    },
    verification: {
      active_poc: summary.active_poc,
      fix_verification: summary.fix_verification,
    },
    summary_metrics: {
      total_findings: Number(summary.total_findings || findings.length || 0),
      raw_findings_total: Number(summary.raw_findings_total || findings.length || 0),
      deduplicated_findings: Number(summary.total_findings || findings.length || 0),
      duplicate_findings_removed: Number(summary.duplicate_findings_removed || 0),
      open_findings: Number(summary.open_findings || 0),
      reviewed_findings: Number(summary.reviewed_findings || 0),
      files_scanned: Number(executive.files_scanned || 0),
      files_impacted: Number(summary.files_impacted || executive.total_files_impacted || 0),
      severity_distribution: severityDistribution,
      risk_score: Number(summary.risk_score || executive.risk_score || 0),
      risk_rating: String(summary.risk_rating || executive.risk_rating || "Unknown"),
      top_vulnerability_types: nonEmptyArray(summary.top_vulnerability_types) || nonEmptyArray(executive.top_vulnerability_types) || derivedTopTypes,
      top_owasp_categories: nonEmptyArray(summary.top_owasp_categories) || nonEmptyArray(executive.top_owasp_categories) || derivedTopOwasp,
      affected_modules: nonEmptyArray(summary.affected_modules) || nonEmptyArray(executive.affected_modules) || derivedModules,
    },
  };
}

export function projectScanView(scan: ScanView, requestedRole?: UserRole): ScanView {
  const role = normalizeUserRole(requestedRole || scan.role || scan.report.executive_summary.scan_role);
  const canonical =
    scan.canonicalScan ||
    buildCanonicalScanObject({
      scanId: scan.scanId,
      projectPath: scan.projectPath,
      requestedRole: scan.role,
      scanPreset: scan.report.executive_summary.scan_preset || "standard",
      startedAt: scan.startedAt,
      completedAt: scan.completedAt,
      report: scan.report,
    });
  const projection = buildProjectionMetadata(canonical, role);
  const report = projectReport(scan.report, canonical, projection);

  return {
    ...scan,
    role,
    canonicalScan: canonical,
    projection,
    report,
  };
}

function projectReport(report: UniversalScanReport, canonical: CanonicalScanObject, projection: RoleProjectionMetadata): UniversalScanReport {
  const projected = cloneStructured(report);
  const role = projection.role;
  const summary = projected.vulnerability_fixed_code_report.summary;
  const executive = projected.executive_summary;
  const roleAware = {
    ...(projected.role_aware_report || projected.vulnerability_fixed_code_report.role_aware_report || {}),
    metadata: {
      ...((projected.role_aware_report || projected.vulnerability_fixed_code_report.role_aware_report || {}).metadata || {}),
      scan_role: role,
      projection_role: role,
      canonical_scan_id: canonical.scan_id,
      canonical_schema_version: canonical.schema_version,
      allowed_sections: projection.allowed_sections,
      redacted_fields: projection.redacted_fields,
      projection_reason: projection.projection_reason,
      inclusion_policy: projection.inclusion_policy,
      redaction_policy: projection.redaction_policy,
      scanner_invoked: false,
      projection_generated_at: projection.generated_at,
    },
  };

  projected.role_aware_report = roleAware;
  projected.vulnerability_fixed_code_report.role_aware_report = roleAware;
  projected.executive_summary.scan_role = role;
  projected.vulnerability_fixed_code_report.scan_role = role;
  projected.executive_summary.severity_distribution = { ...canonical.severity_distribution };
  summary.severity_distribution = { ...canonical.severity_distribution };
  projected.executive_summary.total_vulnerabilities = canonical.summary_metrics.total_findings;
  projected.executive_summary.deduplicated_vulnerabilities = canonical.summary_metrics.deduplicated_findings;
  projected.executive_summary.duplicate_findings_removed = canonical.summary_metrics.duplicate_findings_removed;
  summary.total_findings = canonical.summary_metrics.deduplicated_findings;
  summary.raw_findings_total = canonical.summary_metrics.raw_findings_total;
  summary.duplicate_findings_removed = canonical.summary_metrics.duplicate_findings_removed;
  summary.risk_score = canonical.summary_metrics.risk_score;
  summary.risk_rating = canonical.summary_metrics.risk_rating;

  if (role === "Management") {
    applyManagementProjection(projected, canonical);
  } else if (role === "Auditor") {
    projected.vulnerability_fixed_code_report.findings = projected.vulnerability_fixed_code_report.findings.map(redactFindingForAudit);
  }

  return projected;
}

function buildProjectionMetadata(canonical: CanonicalScanObject, role: UserRole): RoleProjectionMetadata {
  const rules = ROLE_SECTION_RULES[role] || ROLE_SECTION_RULES["Security Analyst"];
  return {
    role,
    source_scan_id: canonical.scan_id,
    source_schema_version: canonical.schema_version,
    generated_at: new Date().toISOString(),
    visibility: rules.visibility,
    projection_reason: `Role projection derived from canonical scan ${canonical.scan_id}; scanner was not invoked.`,
    inclusion_policy: rules.inclusionPolicy,
    redaction_policy: rules.redactionPolicy,
    allowed_sections: rules.sections,
    redacted_fields: rules.redacted,
    scanner_invoked: false,
  };
}

function applyManagementProjection(report: UniversalScanReport, canonical: CanonicalScanObject): void {
  const executive = report.executive_summary;
  const summary = report.vulnerability_fixed_code_report.summary;
  const existingManagement = (executive.management_summary || {}) as NonNullable<typeof executive.management_summary>;
  const canonicalFindings = canonical.deduplicated_findings || canonical.raw_findings || [];
  const managementSeverity = normalizeSeverityDistribution(
    existingManagement.severity_distribution_raw || existingManagement.severity_distribution,
    canonical.severity_distribution,
  );
  const existingSeverityBreakdown = Array.isArray(existingManagement.severity_breakdown_groups)
    ? existingManagement.severity_breakdown_groups
    : [];

  executive.management_summary = {
    ...existingManagement,
    total_findings: canonical.summary_metrics.total_findings,
    deduplicated_vulnerabilities: canonical.summary_metrics.deduplicated_findings,
    active_risk_findings: (managementSeverity.Critical || 0) + (managementSeverity.High || 0),
    severity_distribution: managementSeverity,
    severity_distribution_raw: managementSeverity,
    top_vulnerability_types: nonEmptyArray(existingManagement.top_vulnerability_types) || canonical.summary_metrics.top_vulnerability_types || buildTopVulnerabilityTypes(canonicalFindings),
    top_owasp_categories: nonEmptyArray(existingManagement.top_owasp_categories) || canonical.summary_metrics.top_owasp_categories || buildTopOwaspCategories(canonicalFindings),
    affected_modules: nonEmptyArray(existingManagement.affected_modules) || canonical.summary_metrics.affected_modules || buildAffectedModules(canonicalFindings),
    severity_breakdown_groups: existingSeverityBreakdown.length ? existingSeverityBreakdown : buildSeverityBreakdownGroups(canonicalFindings),
    risk_score: canonical.summary_metrics.risk_score,
    risk_rating: canonical.summary_metrics.risk_rating,
  };
  executive.severity_distribution = managementSeverity;
  executive.total_vulnerabilities = canonical.summary_metrics.total_findings;
  executive.deduplicated_vulnerabilities = canonical.summary_metrics.deduplicated_findings;
  summary.severity_distribution = managementSeverity;
  summary.total_findings = canonical.summary_metrics.deduplicated_findings;
  summary.open_findings = 0;
  summary.reviewed_findings = canonical.summary_metrics.deduplicated_findings;
  report.vulnerability_fixed_code_report.findings = [];
  report.vulnerability_fixed_code_report.auto_fix_recommendations = [];
}

function redactFindingForAudit(finding: VulnerabilityFinding): VulnerabilityFinding {
  return {
    ...finding,
    original_code: "",
    fixed_code: "",
    ai_suggested_fix: undefined,
    patch_preview: "",
    proof_of_concept: undefined,
    proof_of_concept_template: undefined,
    active_poc: finding.active_poc
      ? {
          ...finding.active_poc,
          command: finding.active_poc.command ? "[redacted]" : undefined,
          output: finding.active_poc.output ? "[redacted]" : undefined,
        }
      : undefined,
    fix_verification: finding.fix_verification
      ? {
          ...finding.fix_verification,
          post_fix_execution: finding.fix_verification.post_fix_execution
            ? { ...finding.fix_verification.post_fix_execution, command: "[redacted]", output: "[redacted]" }
            : undefined,
          build_verification: finding.fix_verification.build_verification
            ? { ...finding.fix_verification.build_verification, command: "[redacted]", output: "[redacted]" }
            : undefined,
          test_verification: finding.fix_verification.test_verification
            ? { ...finding.fix_verification.test_verification, command: "[redacted]", output: "[redacted]" }
            : undefined,
        }
      : undefined,
  };
}

function buildTaxonomyCounts(findings: VulnerabilityFinding[]): CanonicalScanObject["cwe_owasp_cve_data"] {
  const cwe: Record<string, number> = {};
  const owasp: Record<string, number> = {};
  const cve: Record<string, number> = {};
  const advisory: Record<string, number> = {};
  for (const finding of findings) {
    increment(cwe, finding.cwe_id);
    increment(owasp, finding.owasp_mapping);
    for (const item of finding.cve_ids || []) {
      increment(cve, item);
    }
    for (const item of finding.advisory_ids || []) {
      increment(advisory, item);
    }
  }
  return { cwe, owasp, cve, advisory };
}

function summarizeSeverity(findings: VulnerabilityFinding[]): Record<string, number> {
  const summary = emptySeverityDistribution();
  for (const finding of findings) {
    const severity = SEVERITIES.includes(finding.severity) ? finding.severity : "Info";
    summary[severity] += 1;
  }
  return summary;
}

function buildSeverityBreakdownGroups(findings: VulnerabilityFinding[]): Array<Record<string, unknown>> {
  const bySeverity = new Map<Severity, Map<string, {
    severity: Severity;
    title: string;
    cwe: string;
    owasp: string;
    count: number;
    modules: Set<string>;
    instances: Array<Record<string, unknown>>;
  }>>();
  for (const finding of findings) {
    const findingRecord = finding as unknown as Record<string, unknown>;
    const severity = SEVERITIES.includes(finding.severity) ? finding.severity : "Info";
    const title = String(finding.vulnerability_title || findingRecord.title || finding.rule_id || "Security Issue").trim();
    const cwe = String(finding.cwe_id || "N/A").trim() || "N/A";
    const owasp = String(finding.owasp_mapping || "N/A").trim() || "N/A";
    const key = `${title.toLowerCase()}::${cwe.toLowerCase()}`;
    if (!bySeverity.has(severity)) {
      bySeverity.set(severity, new Map());
    }
    const severityMap = bySeverity.get(severity)!;
    if (!severityMap.has(key)) {
      severityMap.set(key, {
        severity,
        title,
        cwe,
        owasp,
        count: 0,
        modules: new Set(),
        instances: [],
      });
    }
    const group = severityMap.get(key)!;
    const filePath = String(finding.file_path || "unknown");
    const lineNumber = Number(finding.line_number || 1);
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
  return SEVERITIES.map((severity) => {
    const groups = Array.from(bySeverity.get(severity)?.values() || [])
      .sort((left, right) => right.count - left.count || left.title.localeCompare(right.title))
      .map((group) => ({
        severity: group.severity,
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

function buildTopVulnerabilityTypes(findings: VulnerabilityFinding[]): Array<{ type: string; count: number }> {
  const counts: Record<string, number> = {};
  for (const finding of findings) {
    const findingRecord = finding as unknown as Record<string, unknown>;
    const title = String(finding.vulnerability_title || findingRecord.title || finding.rule_id || "Security Issue").trim();
    increment(counts, title);
  }
  return sortCountRows(counts).map(([type, count]) => ({ type, count }));
}

function buildTopOwaspCategories(findings: VulnerabilityFinding[]): Array<{ owasp_category: string; count: number }> {
  const counts: Record<string, number> = {};
  for (const finding of findings) {
    increment(counts, finding.owasp_mapping);
  }
  return sortCountRows(counts).map(([owasp_category, count]) => ({ owasp_category, count }));
}

function buildAffectedModules(findings: VulnerabilityFinding[]): Array<{ module: string; count: number; critical: number; high: number }> {
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
  const normalized = String(value || "root").replaceAll("\\", "/");
  const parts = normalized.split("/").filter(Boolean);
  return parts[0] || "root";
}

function fileNameFromPath(value: unknown): string {
  const normalized = String(value || "unknown").replaceAll("\\", "/");
  const parts = normalized.split("/").filter(Boolean);
  return parts[parts.length - 1] || "unknown";
}

function nonEmptyArray<T>(value: T[] | undefined): T[] | undefined {
  return Array.isArray(value) && value.length > 0 ? cloneStructured(value) : undefined;
}

function normalizeSeverityDistribution(input: unknown, fallback?: Record<string, number>): Record<string, number> {
  const result = emptySeverityDistribution();
  const source = typeof input === "object" && input !== null ? (input as Record<string, unknown>) : fallback || {};
  for (const severity of SEVERITIES) {
    result[severity] = Number(source?.[severity] || fallback?.[severity] || 0);
  }
  return result;
}

function emptySeverityDistribution(): Record<string, number> {
  return { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };
}

function increment(target: Record<string, number>, key: unknown): void {
  const normalized = String(key || "").trim();
  if (!normalized || normalized === "N/A") {
    return;
  }
  target[normalized] = (target[normalized] || 0) + 1;
}

function cloneStructured<T>(payload: T): T {
  return JSON.parse(JSON.stringify(payload)) as T;
}
