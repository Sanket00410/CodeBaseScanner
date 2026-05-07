export type Severity = "Critical" | "High" | "Medium" | "Low" | "Info";
export type UserRole = "Admin" | "Security Analyst" | "Developer" | "Auditor" | "Management";
export type ScanPreset = "fast" | "standard" | "deep";
export type ScanTargetType = "auto" | "local" | "http" | "ssh";
export type ThreatModelFramework = "STRIDE" | "DREAD" | "OWASP" | "PASTA";

export interface ScmDiffContext {
  diffBaseRef?: string;
  diffHeadRef?: string;
  changedFilesFile?: string;
  changedFilesJson?: string;
  changedLinesJson?: string;
}

export interface ScanRequest {
  projectPath: string;
  requestedBy?: string;
  role?: UserRole;
  scanPreset?: ScanPreset;
  targetType?: ScanTargetType;
  scmContext?: ScmDiffContext;
}

export interface ScanProgressPayload {
  scanId: string;
  stage: string;
  progress: number;
  message: string;
  currentFile?: string;
  status: "running" | "paused" | "completed" | "failed" | "stopped";
}

export interface ScanControlActionResult {
  scanId: string;
  success: boolean;
  state: "running" | "paused" | "stopped";
  message: string;
}

export interface ExportRequest {
  scanId: string;
  role?: UserRole;
  reportType: "existing" | "vulnerability" | "fixes" | "finding_details" | "combined" | "management";
  format: "json" | "xml" | "html" | "pdf" | "sarif" | "csv" | "patch";
  reportStyle?: "classic" | "modern";
  managementContext?: ManagementReportContext;
}

export interface ThreatModelRequest {
  projectPath: string;
  requestedBy?: string;
  framework?: ThreatModelFramework;
}

export interface ThreatModelSystemOverview {
  application_type: string;
  main_components: string[];
  external_integrations: string[];
  technology_stack: string[];
}

export interface ThreatModelEntryPoint {
  name: string;
  type: string;
  file: string;
  line: number;
  exposure: "Public" | "Authenticated" | "Internal";
  details: string;
}

export interface ThreatModelTrustBoundary {
  from: string;
  to: string;
  data: string[];
  description: string;
}

export interface ThreatModelDataFlow {
  source: string;
  destination: string;
  data: string;
  description: string;
}

export interface ThreatModelAsset {
  asset_id: string;
  name: string;
  category: string;
  description: string;
  location: string;
  sensitivity: "High" | "Medium" | "Low";
  evidence?: Array<{
    file: string;
    line: number;
    excerpt: string;
  }>;
}

export interface ThreatModelSecurityObjective {
  asset_id: string;
  confidentiality: string;
  integrity: string;
  availability: string;
  rationale: string;
}

export interface ThreatModelThreat {
  threat_id?: string;
  title: string;
  component: string;
  stride_category: "Spoofing" | "Tampering" | "Repudiation" | "Information Disclosure" | "Denial of Service" | "Elevation of Privilege";
  framework_category?: string;
  framework_notes?: string;
  owasp_category?: string;
  pasta_stage?: string;
  dread_breakdown?: {
    damage: number;
    reproducibility: number;
    exploitability: number;
    affected_users: number;
    discoverability: number;
  };
  description: string;
  abuse_case: string;
  impact: "High" | "Medium" | "Low";
  likelihood: "High" | "Medium" | "Low";
  exposure: "Public" | "Authenticated" | "Internal";
  risk_score?: number;
  risk_level?: "Critical" | "High" | "Medium" | "Low";
  review_status?: "Pending reviewer validation" | "Validated by reviewer" | "Not reviewed";
  root_cause?: string;
  evidence?: Array<{
    file: string;
    line: number;
    excerpt: string;
  }>;
  mitigation: string;
}

export interface ThreatModelCodeMapping {
  threat_id: string;
  component: string;
  file: string;
  line: number;
  root_cause: string;
  cwe?: string;
}

export interface ThreatModelValidationPlanItem {
  threat_id: string;
  check: string;
  expected_verification: string;
}

export interface ThreatModelTraceabilityItem {
  threat_id: string;
  evidence: string;
  status: string;
}

export interface ThreatModelReport {
  schema_version: "codesentinelx.threat_model.v1";
  target_path: string;
  target_type: "file" | "folder" | "unknown";
  generated_at: string;
  framework: ThreatModelFramework;
  system_overview: ThreatModelSystemOverview;
  assets: ThreatModelAsset[];
  security_objectives: ThreatModelSecurityObjective[];
  entry_points: ThreatModelEntryPoint[];
  trust_boundaries: ThreatModelTrustBoundary[];
  data_flows: ThreatModelDataFlow[];
  code_mappings: ThreatModelCodeMapping[];
  threats: ThreatModelThreat[];
  validation_plan: ThreatModelValidationPlanItem[];
  traceability: ThreatModelTraceabilityItem[];
  residual_risk: string[];
  assumptions: string[];
  diagram: string;
  summary: {
    source_files_analyzed: number;
    assets: number;
    entry_points: number;
    threats: number;
  };
}

export interface ThreatModelResult {
  report: ThreatModelReport;
  jsonPath: string;
  htmlPath: string;
  mermaidPath: string;
}

export interface ManagementReportContext {
  portfolioSummary?: PortfolioSummary | null;
  scanHistory?: Array<{
    scanId: string;
    projectPath: string;
    startedAt: string;
    completedAt: string;
    riskScore?: number;
    totalFindings: number;
    criticalFindings?: number;
    highFindings?: number;
    mediumFindings?: number;
    lowFindings?: number;
    infoFindings?: number;
    reviewedFindings?: number;
    suppressedCount?: number;
  }>;
}

export interface CanonicalScanSummary {
  total_findings: number;
  raw_findings_total: number;
  deduplicated_findings: number;
  duplicate_findings_removed: number;
  open_findings: number;
  reviewed_findings: number;
  files_scanned: number;
  files_impacted: number;
  severity_distribution: Record<string, number>;
  risk_score: number;
  risk_rating: string;
  top_vulnerability_types: Array<{ type: string; count: number }>;
  top_owasp_categories: Array<{ owasp_category: string; count: number }>;
  affected_modules: Array<{ module: string; count: number; critical: number; high: number }>;
}

export interface CanonicalScanObject {
  schema_version: "codesentinelx.canonical_scan.v1";
  scan_id: string;
  target_path: string;
  target_type: "file" | "folder" | "unknown";
  requested_role: UserRole;
  execution_role: UserRole;
  scan_preset: ScanPreset;
  started_at: string;
  completed_at: string;
  tool_execution_status: Record<string, ToolchainStatusEntry>;
  raw_findings: VulnerabilityFinding[];
  deduplicated_findings: VulnerabilityFinding[];
  severity_distribution: Record<string, number>;
  cwe_owasp_cve_data: {
    cwe: Record<string, number>;
    owasp: Record<string, number>;
    cve: Record<string, number>;
    advisory: Record<string, number>;
  };
  evidence: {
    toolchain_execution?: ToolchainExecutionSummary;
    deterministic_replay?: DeterministicReplaySummary;
    report_integrity_chain?: ReportIntegrityChain;
  };
  verification: {
    active_poc?: VulnerabilityFixedCodeReport["summary"]["active_poc"];
    fix_verification?: VulnerabilityFixedCodeReport["summary"]["fix_verification"];
  };
  summary_metrics: CanonicalScanSummary;
}

export interface RoleProjectionMetadata {
  role: UserRole;
  source_scan_id: string;
  source_schema_version: CanonicalScanObject["schema_version"];
  generated_at: string;
  visibility: "full" | "security" | "developer" | "redacted" | "summary";
  projection_reason: string;
  inclusion_policy: string;
  redaction_policy: string;
  allowed_sections: string[];
  redacted_fields: string[];
  scanner_invoked: false;
}

export interface ExistingControl {
  control_id: string;
  name: string;
  category: string;
  description: string;
  status: string;
  coverage_level: string;
  standard_mappings: string[];
  evidence: Array<Record<string, unknown>>;
}

export interface ComplianceMatrixItem {
  standard: string;
  control_count: number;
  status: string;
}

export type ComplianceScanProfile = "codebase";

export interface ProfileComplianceRow {
  id: string;
  title: string;
  status: "covered" | "gap" | "not_applicable";
  finding_count: number;
  control_count: number;
  count: number;
}

export interface ProfileComplianceFramework {
  framework_id: string;
  framework_name: string;
  version: string;
  label: string;
  prefix: string;
  applicable: boolean;
  summary: {
    covered: number;
    gap: number;
    not_applicable: number;
    mapped_findings: number;
    mapped_controls: number;
  };
  rows: ProfileComplianceRow[];
}

export interface ProfileComplianceReport {
  scan_profile: ComplianceScanProfile;
  scan_profile_label: string;
  framework_versions: {
    owasp_top_10: string;
    owasp_api_top_10: string;
    asvs: string;
    wstg: string;
  };
  applicable_framework_ids: string[];
  frameworks: ProfileComplianceFramework[];
  summary: {
    frameworks_total: number;
    frameworks_applicable: number;
    items_covered: number;
    items_gap: number;
    items_not_applicable: number;
    mapped_findings_total: number;
    mapped_controls_total: number;
  };
}

export interface ExistingImplementationReport {
  report_type: "existing_implementation";
  title: string;
  target_path: string;
  generated_at: string;
  summary: {
    implemented_controls: number;
    category_distribution: Record<string, number>;
    coverage_levels: Record<string, number>;
    standards_coverage: Record<string, number>;
  };
  controls: ExistingControl[];
  compliance_matrix: ComplianceMatrixItem[];
  profile_compliance?: ProfileComplianceReport;
  enterprise_assurance?: EnterpriseAssuranceSummary;
}

export interface VulnerabilityFinding {
  finding_uid: string;
  vulnerability_title: string;
  vulnerability_type?: string;
  description?: string;
  severity: Severity;
  cvss_score: number;
  cwe_id: string;
  owasp_mapping: string;
  file_path: string;
  line_number: number;
  business_impact: string;
  recommendation: string;
  original_code: string;
  fixed_code: string;
  ai_suggested_fix?: string;
  ai_remediation_summary?: string;
  ai_validation_steps?: string;
  ai_fix_source?: string;
  ai_fix_confidence_label?: string;
  ai_fix_confidence_score?: number;
  ai_fix_grounded?: boolean;
  ai_grounding_notes?: string;
  patch_preview: string;
  remediation_confidence?: string;
  code_evidence_excerpt?: string;
  source_line_snippet?: string;
  code_owner?: string;
  rule_confidence?: number;
  rule_confidence_label?: string;
  git_diff_file_changed?: boolean;
  git_diff_line_changed?: boolean;
  dependency_reachability?: {
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
  };
  attack_scenario?: string;
  exploitation_example?: string;
  proof_of_concept?: string;
  proof_of_concept_template?: string;
  cve_ids?: string[];
  advisory_ids?: string[];
  dependency_name?: string;
  dependency_version?: string;
  dependency_id?: string;
  known_exploited?: boolean;
  exploit_maturity?: string;
  exploitability_context?: string;
  release_gate_action?: string;
  active_poc?: {
    mode?: string;
    family?: string;
    command?: string;
    status?: string;
    executed?: boolean;
    exit_code?: number | null;
    output?: string;
    line_tested?: number;
    verification_basis?: string;
    confidence?: number | null;
  };
  fix_verification?: {
    performed?: boolean;
    result?: string;
    reason?: string;
    pre_fix_status?: string;
    post_fix_status?: string;
    post_fix_execution?: {
      command?: string;
      status?: string;
      exit_code?: number | null;
      output?: string;
    };
    build_verification?: {
      command?: string;
      status?: string;
      exit_code?: number | null;
      output?: string;
    };
    test_verification?: {
      command?: string;
      status?: string;
      exit_code?: number | null;
      output?: string;
    };
  };
  evidence_replay_pack?: {
    enabled?: boolean;
    mode?: string;
    inferred_tool?: string;
    recorded?: boolean;
    env_fingerprint?: {
      os?: string;
      os_release?: string;
      platform?: string;
      architecture?: string;
      python_version?: string;
    };
    replay_id?: string;
    timestamp?: string;
    tool?: string;
    command?: string;
    cwd?: string;
    exit_code?: number | null;
    duration_ms?: number;
    output_hashes?: {
      stdout_sha256?: string;
      stderr_sha256?: string;
    };
    output_sizes?: {
      stdout_bytes?: number;
      stderr_bytes?: number;
    };
    record_sha256?: string;
    replay_script?: {
      windows_ps1?: string;
      posix_sh?: string;
    };
    reason?: string;
  };
  rule_id: string;
  fix_artifact_kind?: "exact_patch" | "guidance";
  fix_artifact_label?: string;
  evidence_sources?: string[];
  affected_module?: string;
  tool?: string;
  status?: "Open" | "Reviewed";
  reviewed_by?: string;
  reviewed_at?: string;
}

export interface ToolchainStatusEntry {
  name: string;
  available: boolean;
  command: string;
  source: string;
  message: string;
  selected?: boolean;
  runner_available?: boolean;
  execution?: ToolExecutionStatus;
  display_name?: string;
  description?: string;
  category?: string;
  target_modes?: string[];
  vulnerability_classes?: string[];
  homepage?: string;
  integrated?: boolean;
  recommended_command?: string;
}

export interface ToolExecutionStatus {
  attempted: boolean;
  status: string;
  duration_ms: number;
  findings_count: number;
  errors: string[];
  evidence?: ToolExecutionEvidence[];
}

export interface ToolExecutionEvidence {
  timestamp?: string;
  command?: string;
  cwd?: string;
  exit_code?: number;
  duration_ms?: number;
  stdout_sha256?: string;
  stderr_sha256?: string;
  stdout_bytes?: number;
  stderr_bytes?: number;
  stdout_preview?: string;
  stderr_preview?: string;
}

export interface ToolchainExecutionSummary {
  total_tools: number;
  selected_tools: number;
  available_tools: number;
  integrated_tools: number;
  runner_available_tools: number;
  attempted_tools: number;
  successful_tools: number;
  failed_tools: number;
  unavailable_tools: number;
  no_runner_tools: number;
  skipped_tools: number;
  success_rate_percent: number;
  status_distribution: Record<string, number>;
  failures: Array<{ tool: string; status: string; message: string; errors: string[] }>;
  slowest_tools: Array<{ tool: string; duration_ms: number; findings_count: number; status: string }>;
  total_attempted_duration_ms?: number;
  average_attempted_duration_ms?: number;
  timing_breakdown?: Array<{
    tool: string;
    selected: boolean;
    available: boolean;
    runner_available: boolean;
    attempted: boolean;
    status: string;
    duration_ms: number;
    findings_count: number;
    errors_count: number;
    avg_ms_per_finding?: number | null;
  }>;
}

export interface EnterpriseAssuranceSummary {
  status: "ready" | "warning" | "blocked";
  is_enterprise_ready: boolean;
  scan_profile: ComplianceScanProfile;
  required_tools: string[];
  required_tools_total: number;
  required_tools_ready: number;
  required_tools_coverage_percent: number;
  recommended_tools?: string[];
  recommended_tools_total?: number;
  recommended_tools_ready?: number;
  recommended_tools_coverage_percent?: number;
  toolchain_success_rate_percent: number;
  toolchain_attempted_tools: number;
  toolchain_failed_tools: number;
  toolchain_unavailable_tools: number;
  toolchain_no_runner_tools: number;
  readiness_score: number;
  blockers: string[];
  advisories?: string[];
  recommendation: string;
  quality_benchmark?: QualityBenchmarkSummary;
}

export interface FalsePositiveCandidate {
  finding_uid?: string;
  vulnerability_title?: string;
  severity?: Severity;
  file_path?: string;
  line_number?: number;
  reason_summary?: string;
  reason_detail?: string;
  confidence?: number;
  verification_steps?: string[];
}

export interface FalsePositiveReport {
  policy_note?: string;
  candidate_count?: number;
  candidates?: FalsePositiveCandidate[];
}

export interface RoleAwareReport {
  metadata?: Record<string, unknown>;
  visualization_hints?: Record<string, unknown>;
  cto_board_view?: Record<string, unknown>;
  ciso_security_view?: Record<string, unknown>;
  developer_devops_view?: Record<string, unknown>;
  risk_story_mode?: Record<string, unknown>;
  advanced_features?: Record<string, unknown>;
  enterprise_assurance?: EnterpriseAssuranceSummary;
  false_positive_report?: FalsePositiveReport;
}

export interface DeterministicReplaySummary {
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

export interface ReportIntegrityChain {
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

export interface DataQualitySummary {
  raw_findings: number;
  deduplicated_findings: number;
  duplicate_findings_removed: number;
  dedup_ratio_percent: number;
  suppressed_findings: number;
  suppression_rate_percent: number;
  tool_success_rate_percent: number;
  tool_attempted_count: number;
  coverage_confidence: string;
  coverage_confidence_score: number;
  unknown_rule_count: number;
  unknown_cwe_count: number;
  unknown_owasp_count: number;
  unknown_taxonomy_count: number;
  quality_benchmark?: QualityBenchmarkSummary;
}

export interface QualityBenchmarkSummary {
  enabled: boolean;
  configured: boolean;
  benchmark_status: "ready" | "warning" | "blocked" | "not_configured" | "disabled";
  benchmark_name: string;
  benchmark_file: string;
  benchmark_description?: string;
  cases_total: number;
  expected_present: number;
  expected_absent: number;
  true_positives: number;
  false_positives: number;
  false_negatives: number;
  true_negatives: number;
  precision_percent: number;
  recall_percent: number;
  f1_percent: number;
  false_positive_rate_percent: number;
  threshold_precision_percent: number;
  threshold_recall_percent: number;
  threshold_f1_percent: number;
  matched_case_ids: string[];
  missing_case_ids: string[];
  unexpected_finding_ids: string[];
  gate_blockers: string[];
  gate_advisories: string[];
}

export interface VulnerabilityFixedCodeReport {
  report_type: "vulnerability_fixed_code";
  title: string;
  target_path: string;
  generated_at: string;
  scan_role?: string;
  summary: {
    total_findings: number;
    raw_findings_total: number;
    duplicate_findings_removed: number;
    suppressed_by_policy?: number;
    severity_distribution: Record<string, number>;
    risk_score: number;
    risk_rating: string;
    active_risk_findings: number;
    files_impacted: number;
    top_vulnerability_types: Array<{ type: string; count: number }>;
    top_owasp_categories: Array<{ owasp_category: string; count: number }>;
    affected_modules: Array<{ module: string; count: number; critical: number; high: number }>;
    release_gate_distribution?: Record<string, number>;
    risk_intelligence?: {
      findings_with_cve: number;
      findings_cvss_ge_7: number;
      known_exploited_findings: number;
    };
    git_diff_tracking?: {
      enabled: boolean;
      changed_files: number;
      changed_lines: number;
      findings_on_changed_files: number;
      findings_on_changed_lines: number;
    };
    auth_abuse_session_security?: {
      total_findings: number;
      severity_distribution: Record<string, number>;
      top_vulnerability_types: Array<{ type: string; count: number }>;
      affected_modules: Array<{ module: string; count: number; critical: number; high: number }>;
      affected_files: Array<{ file: string; folder: string; count: number; critical: number; high: number }>;
      issue_file_mapping?: Array<{ issue_type: string; file: string; folder: string; count: number; critical: number; high: number }>;
    };
    open_findings?: number;
    reviewed_findings?: number;
    scan_profile?: ComplianceScanProfile;
    toolchain_execution?: ToolchainExecutionSummary;
    active_poc?: {
      executed: number;
      passed?: number;
      verified?: number;
      failed: number;
      inconclusive?: number;
      skipped: number;
    };
    fix_verification?: {
      performed: number;
      verified_fixed: number;
      verification_failed: number;
      inconclusive: number;
      not_applicable: number;
      skipped: number;
    };
    enterprise_assurance?: EnterpriseAssuranceSummary;
    false_positive_candidates?: number;
    deterministic_replay?: DeterministicReplaySummary;
    report_integrity_chain?: ReportIntegrityChain;
    data_quality?: DataQualitySummary;
    policy_workflow?: Record<string, unknown>;
    suppression_lifecycle?: Record<string, unknown>;
  };
  findings: VulnerabilityFinding[];
  auto_fix_recommendations: Array<Record<string, unknown>>;
  toolchain_status: Record<string, ToolchainStatusEntry>;
  false_positive_report?: FalsePositiveReport;
  role_aware_report?: RoleAwareReport;
  deterministic_replay?: DeterministicReplaySummary;
  report_integrity_chain?: ReportIntegrityChain;
}

export interface ExecutiveSummary {
  target_path: string;
  generated_at: string;
  scan_role?: string;
  files_scanned: number;
  total_vulnerabilities: number;
  deduplicated_vulnerabilities?: number;
  duplicate_findings_removed?: number;
  total_files_impacted?: number;
  active_risk_findings?: number;
  assessment_confidence?: string;
  severity_distribution: Record<string, number>;
  risk_score: number;
  risk_rating: string;
  top_vulnerability_types?: Array<{ type: string; count: number }>;
  top_owasp_categories?: Array<{ owasp_category: string; count: number }>;
  affected_modules?: Array<{ module: string; count: number; critical: number; high: number }>;
  recommended_action_plan?: string[];
  implemented_controls?: number;
  scan_profile?: ComplianceScanProfile;
  scan_profile_label?: string;
  scan_preset?: ScanPreset;
  scan_preset_label?: string;
  toolchain_execution?: ToolchainExecutionSummary;
  enterprise_assurance?: EnterpriseAssuranceSummary;
  data_quality?: DataQualitySummary;
  framework_versions?: {
    owasp_top_10: string;
    owasp_api_top_10: string;
    asvs: string;
    wstg: string;
  };
  deterministic_replay?: DeterministicReplaySummary;
  report_integrity_chain?: ReportIntegrityChain;
  policy_workflow?: Record<string, unknown>;
  suppression_lifecycle?: Record<string, unknown>;
  management_summary?: {
    total_findings: number;
    deduplicated_vulnerabilities: number;
    active_risk_findings: number;
    severity_distribution: Record<string, number>;
    severity_distribution_raw?: Record<string, number>;
    severity_breakdown_groups?: Array<Record<string, unknown>>;
    top_vulnerability_types?: Array<{ type: string; count: number }>;
    top_owasp_categories?: Array<{ owasp_category: string; count: number }>;
    affected_modules?: Array<{ module: string; count: number; critical: number; high: number }>;
    affected_files?: Array<{ file: string; folder: string; count: number; critical: number; high: number }>;
    affected_folders?: Array<{ folder: string; count: number; critical: number; high: number }>;
    risk_score: number;
    risk_rating: string;
  };
}

export interface UniversalScanReport {
  scanner: {
    name: string;
    version: string;
  };
  executive_summary: ExecutiveSummary;
  existing_implementation_report: ExistingImplementationReport;
  vulnerability_fixed_code_report: VulnerabilityFixedCodeReport;
  profile_compliance?: ProfileComplianceReport;
  false_positive_report?: FalsePositiveReport;
  role_aware_report?: RoleAwareReport;
  [key: string]: unknown;
}

export interface FindingReviewState {
  status: "Open" | "Reviewed";
  reviewedBy?: string;
  reviewedAt?: string;
}

export interface ScanRecord {
  scanId: string;
  projectPath: string;
  requestedBy: string;
  role: UserRole;
  startedAt: string;
  completedAt: string;
  canonicalScan?: CanonicalScanObject;
  projectionCache?: Partial<Record<UserRole, RoleProjectionMetadata>>;
  report: UniversalScanReport;
  findingStates: Record<string, FindingReviewState>;
}

export interface ScanHistoryItem {
  scanId: string;
  projectPath: string;
  startedAt: string;
  completedAt: string;
  canonicalScanAvailable?: boolean;
  roleViewsAvailable?: UserRole[];
  risk: string;
  riskScore?: number;
  totalFindings: number;
  criticalFindings?: number;
  highFindings?: number;
  mediumFindings?: number;
  lowFindings?: number;
  infoFindings?: number;
  reviewedFindings?: number;
  suppressedCount?: number;
  topModule?: string;
}

export interface PortfolioSummary {
  scansTotal: number;
  repositoriesTotal: number;
  trendDirection: "improving" | "declining" | "stable" | "unavailable";
  trendDelta: number;
  hotModules: Array<{ module: string; count: number }>;
  recurringCwe: Array<{ cwe: string; count: number }>;
  fixVelocityPercent: number;
  suppressionDriftScore: number;
}

export interface AuditEntry {
  id: string;
  scanId?: string;
  action: string;
  actor: string;
  role: UserRole;
  details: string;
  createdAt: string;
}

export interface ScanView {
  scanId: string;
  projectPath: string;
  requestedBy: string;
  role: UserRole;
  startedAt: string;
  completedAt: string;
  canonicalScan?: CanonicalScanObject;
  projection?: RoleProjectionMetadata;
  report: UniversalScanReport;
}

export interface ToolManagerAuthConfig {
  enabled: boolean;
  allowedEmailMasked: string;
  authMode: "totp_only" | "smtp_otp_mfa";
  otpRequired: boolean;
  otpTtlSeconds: number;
  sessionTtlSeconds: number;
  mfaRequired: boolean;
  mfaIssuer: string;
  smtpConfigured: boolean;
  sessionValid: boolean;
  sessionEmail?: string;
  sessionExpiresAt?: string;
  message: string;
}

export interface ToolManagerOtpResult {
  success: boolean;
  message: string;
  expiresInSeconds?: number;
}

export interface ToolManagerVerifyResult {
  success: boolean;
  message: string;
  authToken?: string;
  expiresAt?: string;
  email?: string;
}
