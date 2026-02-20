export type Severity = "Critical" | "High" | "Medium" | "Low" | "Info";
export type UserRole = "Admin" | "Security Analyst" | "Developer" | "Auditor";

export interface RuntimeAuthProfile {
  token?: string;
  cookie?: string;
  headerName?: string;
  headerValue?: string;
}

export interface ScanRequest {
  projectPath: string;
  requestedBy?: string;
  role?: UserRole;
  runtimeAuth?: RuntimeAuthProfile;
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
  reportType: "existing" | "vulnerability" | "fixes" | "combined";
  format: "json" | "html" | "pdf" | "sarif" | "csv" | "patch";
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

export type ComplianceScanProfile = "codebase" | "website" | "localhost" | "ip";

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
  patch_preview: string;
  rule_id: string;
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
  display_name?: string;
  description?: string;
  category?: string;
  target_modes?: string[];
  vulnerability_classes?: string[];
  homepage?: string;
  integrated?: boolean;
  recommended_command?: string;
}

export interface VulnerabilityFixedCodeReport {
  report_type: "vulnerability_fixed_code";
  title: string;
  target_path: string;
  generated_at: string;
  summary: {
    total_findings: number;
    raw_findings_total: number;
    duplicate_findings_removed: number;
    severity_distribution: Record<string, number>;
    risk_score: number;
    risk_rating: string;
    active_risk_findings: number;
    files_impacted: number;
    top_vulnerability_types: Array<{ type: string; count: number }>;
    top_owasp_categories: Array<{ owasp_category: string; count: number }>;
    affected_modules: Array<{ module: string; count: number; critical: number; high: number }>;
    open_findings?: number;
    reviewed_findings?: number;
    scan_profile?: ComplianceScanProfile;
  };
  findings: VulnerabilityFinding[];
  auto_fix_recommendations: Array<Record<string, unknown>>;
  toolchain_status: Record<string, ToolchainStatusEntry>;
}

export interface ExecutiveSummary {
  target_path: string;
  generated_at: string;
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
  framework_versions?: {
    owasp_top_10: string;
    owasp_api_top_10: string;
    asvs: string;
    wstg: string;
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
  report: UniversalScanReport;
  findingStates: Record<string, FindingReviewState>;
}

export interface ScanHistoryItem {
  scanId: string;
  projectPath: string;
  startedAt: string;
  completedAt: string;
  risk: string;
  totalFindings: number;
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
  report: UniversalScanReport;
}
