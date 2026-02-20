export type UserRole = "Admin" | "Security Analyst" | "Developer" | "Auditor";
export type Severity = "Critical" | "High" | "Medium" | "Low" | "Info";
export type ToolScanProfile = "codebase" | "website" | "ip";
export type ToolBootstrapMode = "core" | "full";

export interface ExistingControl {
  control_id: string;
  name: string;
  category: string;
  description: string;
  status: string;
  coverage_level: string;
  standard_mappings: string[];
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
    open_findings?: number;
    reviewed_findings?: number;
    top_vulnerability_types: Array<{ type: string; count: number }>;
    top_owasp_categories: Array<{ owasp_category: string; count: number }>;
    affected_modules: Array<{ module: string; count: number; critical: number; high: number }>;
    scan_profile?: ComplianceScanProfile;
  };
  findings: VulnerabilityFinding[];
  toolchain_status: Record<string, ToolchainStatusEntry>;
}

export interface UniversalScanReport {
  scanner: { name: string; version: string };
  executive_summary: {
    target_path: string;
    generated_at: string;
    files_scanned: number;
    total_vulnerabilities: number;
    deduplicated_vulnerabilities?: number;
    duplicate_findings_removed?: number;
    severity_distribution: Record<string, number>;
    risk_score: number;
    risk_rating: string;
    recommended_action_plan?: string[];
    top_owasp_categories?: Array<{ owasp_category: string; count: number }>;
    affected_modules?: Array<{ module: string; count: number; critical: number; high: number }>;
    scan_profile?: ComplianceScanProfile;
    scan_profile_label?: string;
    framework_versions?: {
      owasp_top_10: string;
      owasp_api_top_10: string;
      asvs: string;
      wstg: string;
    };
  };
  existing_implementation_report: ExistingImplementationReport;
  vulnerability_fixed_code_report: VulnerabilityFixedCodeReport;
  profile_compliance?: ProfileComplianceReport;
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

export interface ScanHistoryItem {
  scanId: string;
  projectPath: string;
  startedAt: string;
  completedAt: string;
  risk: string;
  totalFindings: number;
}

export interface AuditLogEntry {
  id: string;
  scanId?: string;
  action: string;
  actor: string;
  role: UserRole;
  details: string;
  createdAt: string;
}

export interface ScanProgress {
  scanId: string;
  stage: string;
  progress: number;
  message: string;
  currentFile?: string;
  status: "running" | "completed" | "failed";
}

export interface ToolCatalogItem {
  name: string;
  display_name: string;
  description: string;
  category: string;
  command: string;
  target_modes: string[];
  vulnerability_classes: string[];
  homepage: string;
  integrated: boolean;
  scan_profiles: ToolScanProfile[];
  host_available?: boolean;
  host_source?: string;
  host_command?: string;
  host_message?: string;
}

export interface ToolActionResult {
  tool: string;
  success: boolean;
  available?: boolean;
  source?: string;
  command?: string;
  message: string;
  outputPath?: string;
  summary?: {
    target?: string;
    filesScanned?: number;
    vulnerabilities?: number;
    risk?: string;
  };
  stdout?: string;
  stderr?: string;
}

export interface ToolBootstrapResult {
  profile: ToolScanProfile | "all";
  mode: ToolBootstrapMode;
  success: boolean;
  total: number;
  ready: number;
  missing: number;
  tools: ToolActionResult[];
  message: string;
  stdout?: string;
  stderr?: string;
}

export interface ResetLocalStateCacheResult {
  success: boolean;
  message: string;
  storeBackupPath?: string;
  toolchainCachePath?: string;
  seedMessage?: string;
  coreWarmup?: {
    ready: number;
    total: number;
    missing: number;
    success: boolean;
  };
}
