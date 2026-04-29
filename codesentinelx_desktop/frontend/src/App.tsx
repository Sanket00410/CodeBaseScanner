import React, { useEffect, useMemo, useRef, useState } from "react";

import BrandMark from "./components/BrandMark";
import GlobeBackdrop from "./components/GlobeBackdrop";
import {
  AuditLogEntry,
  EnterpriseAssuranceSummary,
  PortfolioSummary,
  ManagementReportContext,
  ProfileComplianceReport,
  ReportHistoryItem,
  ResetLocalStateCacheResult,
  ScmDiffContext,
  ScanHistoryItem,
  ScanProgress,
  ScanView,
  ScanPreset,
  ThreatModelResult,
  ThreatModelReport,
  Severity,
  ToolCatalogItem,
  ToolchainExecutionSummary,
  ToolManagerAuthConfig,
  ToolManagerOtpResult,
  ToolManagerVerifyResult,
  ThreatModelFramework,
  ToolScanProfile,
  ToolchainStatusEntry,
  UserRole,
  VulnerabilityFinding,
} from "./types";

type AppTab = "dashboard" | "threat-model" | "existing" | "vulnerabilities" | "compliance" | "history" | "tools" | "help";
type ExportFormat = "json" | "xml" | "html" | "pdf" | "sarif" | "csv" | "patch";
type ExportType = "existing" | "vulnerability" | "fixes" | "finding_details" | "combined" | "management";
type ReportStyle = "classic" | "modern";
type DashboardSection = "overview" | "toolchain" | "assets" | "operations";
type ExistingSection = "summary" | "controls" | "compliance";
type VulnerabilitySection = "queue" | "detail";
type ComplianceSection = "profile" | "matrix" | "actions";
type HistorySection = "scans" | "audits" | "reports";
type ToolManagerSection = "codebase" | "roles" | "policy";
type FindingScope = "all" | "new" | "changed";
type FindingGroupMode = "none" | "module" | "owner";
type WindowMenuKey = "file" | "edit" | "view" | "window" | "help";
type RoleCapabilities = {
  canRunScan: boolean;
  canReviewFindings: boolean;
  canCopyFixes: boolean;
  canManageTools: boolean;
  canProvisionTools: boolean;
};

type RoleExportPreset = {
  title: string;
  description: string;
  reportType: ExportType;
  previewLabel: string;
  scopeLabel: string;
  scopeDetails: string[];
  formats: Array<{
    format: ExportFormat;
    label: string;
    helper: string;
  }>;
};

type HelpGuideSection = {
  id: string;
  title: string;
  lines: string[];
};

function slugifyHelpAnchor(input: string): string {
  return String(input || "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 80) || "section";
}

function parseHelpGuideSections(markdown: string): HelpGuideSection[] {
  const lines = String(markdown || "").replace(/\r\n/g, "\n").split("\n");
  const sections: HelpGuideSection[] = [];
  let current: HelpGuideSection | null = null;

  for (const raw of lines) {
    const line = String(raw || "");
    const h2 = /^##\s+(.+)$/.exec(line);
    if (h2) {
      if (current) {
        sections.push(current);
      }
      const title = h2[1].trim();
      current = {
        id: `help-${slugifyHelpAnchor(title)}`,
        title,
        lines: [],
      };
      continue;
    }
    if (!current) {
      continue;
    }
    current.lines.push(line);
  }
  if (current) {
    sections.push(current);
  }
  return sections;
}

const TABS: Array<{ key: AppTab; label: string; icon: string }> = [
  { key: "dashboard", label: "Code Risk Overview", icon: "CM" },
  { key: "threat-model", label: "Threat Model", icon: "TH" },
  { key: "existing", label: "Secure Coding Practices", icon: "ES" },
  { key: "vulnerabilities", label: "Code Findings", icon: "VR" },
  { key: "compliance", label: "Compliance", icon: "CP" },
  { key: "history", label: "Scan History", icon: "HS" },
  { key: "tools", label: "Analyzer Catalog", icon: "TM" },
  { key: "help", label: "Help", icon: "HP" },
];

const WINDOW_MENU_ITEMS: Array<{ key: WindowMenuKey; label: string }> = [
  { key: "file", label: "File" },
  { key: "edit", label: "Edit" },
  { key: "view", label: "View" },
  { key: "window", label: "Window" },
  { key: "help", label: "Help" },
];

const ROLES: UserRole[] = ["Admin", "Security Analyst", "Developer", "Auditor", "Management"];
const SEVERITY_ORDER: Severity[] = ["Critical", "High", "Medium", "Low", "Info"];
const TOOL_PROFILES: ToolScanProfile[] = ["codebase"];
const ACTIVE_CODEBASE_TOOLS = new Set<string>([
  "checkov",
  "gitleaks",
  "hadolint",
  "osv-scanner",
  "semgrep",
]);
const SCAN_PRESETS: Array<{ key: ScanPreset; label: string; helper: string }> = [
  { key: "fast", label: "Fast", helper: "Faster triage. Disables active PoC checks and uses smaller file budget." },
  { key: "standard", label: "Standard", helper: "Balanced depth/speed for daily secure coding scans." },
  { key: "deep", label: "Deep", helper: "Maximum depth. Full file budget and uncapped active PoC checks." },
];

const TOOL_PROFILE_META: Record<ToolScanProfile, { label: string; icon: string; helper: string }> = {
  codebase: {
    label: "Codebase Tools",
    icon: "CB",
    helper: "Reference-only catalog for secure code analysis engines and code-focused rules.",
  },
};

const ROLE_DRILLDOWN: Array<{ role: UserRole; purpose: string; drillDownUse: string; primaryActions: string }> = [
  {
    role: "Admin",
    purpose: "Govern platform policies and team-level risk posture.",
    drillDownUse: "Escalate from executive trends into cross-project critical issues and ownership.",
    primaryActions: "Policy changes, baseline updates, analyzer governance, exception approvals.",
  },
  {
    role: "Security Analyst",
    purpose: "Triage and validate issues with security context.",
    drillDownUse: "Pivot from module/file counts to exact evidence and exploitability before routing work.",
    primaryActions: "Triage, severity validation, false-positive suppression, handoff to developers.",
  },
  {
    role: "Developer",
    purpose: "Fix vulnerable code with minimal context switching.",
    drillDownUse: "Jump directly from issue row to file/line, original code, and suggested fix.",
    primaryActions: "Patch implementation, review status updates, regression-safe remediation.",
  },
  {
    role: "Auditor",
    purpose: "Produce evidence and compliance-ready reporting.",
    drillDownUse: "Trace each metric back to concrete issues, ownership, and export artifacts.",
    primaryActions: "Audit evidence capture, control verification, export sign-off packages.",
  },
  {
    role: "Management",
    purpose: "Review executive risk posture and release readiness.",
    drillDownUse: "Read board-level summaries, release gates, and high-signal risk trends without noisy detail.",
    primaryActions: "Executive review, risk acceptance, release oversight, portfolio decisions.",
  },
];

const ROLE_SCAN_SCOPE: Record<UserRole, string[]> = {
  Admin: [
    "Semgrep",
    "Gitleaks",
    "Checkov",
    "Hadolint",
    "OSV-Scanner",
  ],
  "Security Analyst": [
    "Semgrep",
    "Gitleaks",
    "Checkov",
    "Hadolint",
    "OSV-Scanner",
  ],
  Developer: ["Semgrep", "Gitleaks", "Checkov", "Hadolint", "OSV-Scanner"],
  Auditor: ["Semgrep", "Gitleaks", "Checkov", "Hadolint", "OSV-Scanner"],
  Management: ["Semgrep", "Gitleaks", "Checkov", "Hadolint", "OSV-Scanner"],
};

const ROLE_CAPABILITIES: Record<UserRole, RoleCapabilities> = {
  Admin: {
    canRunScan: true,
    canReviewFindings: true,
    canCopyFixes: true,
    canManageTools: true,
    canProvisionTools: true,
  },
  "Security Analyst": {
    canRunScan: true,
    canReviewFindings: true,
    canCopyFixes: true,
    canManageTools: true,
    canProvisionTools: true,
  },
  Developer: {
    canRunScan: true,
    canReviewFindings: true,
    canCopyFixes: true,
    canManageTools: false,
    canProvisionTools: false,
  },
  Auditor: {
    canRunScan: true,
    canReviewFindings: true,
    canCopyFixes: false,
    canManageTools: false,
    canProvisionTools: false,
  },
  Management: {
    canRunScan: true,
    canReviewFindings: false,
    canCopyFixes: false,
    canManageTools: false,
    canProvisionTools: false,
  },
};

const ROLE_EXPORT_PRESETS: Record<UserRole, RoleExportPreset> = {
  Admin: {
    title: "Full Scope Export",
    description: "Complete role-scoped report with all permitted sections and evidence.",
    reportType: "combined",
    previewLabel: "Preview Full Scope",
    scopeLabel: "Full scope",
    scopeDetails: [
      "Role-scoped combined report",
      "HTML, PDF, JSON, XML",
      "Backend enforces Admin-only export scope",
    ],
    formats: [
      { format: "html", label: "HTML", helper: "Open the full scope report in a browser." },
      { format: "pdf", label: "PDF", helper: "Generate a board-friendly PDF." },
      { format: "json", label: "JSON", helper: "Export structured evidence for automation." },
      { format: "xml", label: "XML", helper: "Export structured evidence for integrations." },
    ],
  },
  "Security Analyst": {
    title: "Security Analysis Export",
    description: "Findings-first export for triage, validation, and security operations.",
    reportType: "vulnerability",
    previewLabel: "Preview Findings",
    scopeLabel: "Security analysis",
    scopeDetails: [
      "Vulnerability-focused export",
      "HTML, PDF, JSON, XML, SARIF, CSV",
      "Backend enforces security-analysis scope",
    ],
    formats: [
      { format: "html", label: "HTML", helper: "Open the issue report in a browser." },
      { format: "pdf", label: "PDF", helper: "Generate a shareable issue PDF." },
      { format: "json", label: "JSON", helper: "Export issues for downstream tooling." },
      { format: "xml", label: "XML", helper: "Export issues for integrations." },
      { format: "sarif", label: "SARIF", helper: "Export for code-scanning integrations." },
      { format: "csv", label: "CSV", helper: "Export a tabular triage queue." },
    ],
  },
  Developer: {
    title: "Developer Secure Coding Practices",
    description: "Standards-backed secure coding practices and fix guidance for implementation, review, and patching.",
    reportType: "fixes",
    previewLabel: "Preview Practices",
    scopeLabel: "Secure coding",
    scopeDetails: [
      "Developer-focused secure coding report",
      "HTML, PDF, JSON, Patch bundle",
      "Backend enforces developer-practice scope",
    ],
    formats: [
      { format: "html", label: "HTML", helper: "Open the secure coding practices report in a browser." },
      { format: "pdf", label: "PDF", helper: "Generate a shareable secure coding PDF." },
      { format: "json", label: "JSON", helper: "Export secure coding details for downstream tooling." },
      { format: "patch", label: "Patch", helper: "Download patch previews only." },
    ],
  },
  Auditor: {
    title: "Audit / Compliance Export",
    description: "Redacted evidence and control view for audit sign-off.",
    reportType: "existing",
    previewLabel: "Preview Audit View",
    scopeLabel: "Audit / compliance",
    scopeDetails: [
      "Redacted control and assurance export",
      "HTML, PDF, JSON, XML",
      "Backend enforces audit-only scope",
    ],
    formats: [
      { format: "html", label: "HTML", helper: "Open the redacted audit view in a browser." },
      { format: "pdf", label: "PDF", helper: "Generate an audit-ready PDF." },
      { format: "json", label: "JSON", helper: "Export structured audit evidence." },
      { format: "xml", label: "XML", helper: "Export structured audit evidence." },
    ],
  },
  Management: {
    title: "Management Risk Dashboard",
    description: "A board-facing management report with charts, trend lines, compliance mapping, and risk posture summaries.",
    reportType: "management",
    previewLabel: "Preview Dashboard",
    scopeLabel: "Management",
    scopeDetails: [
      "Management-only dashboard report",
      "HTML, PDF, JSON",
      "Backend enforces management-only scope",
    ],
    formats: [
      { format: "html", label: "HTML", helper: "Open the management dashboard in a browser." },
      { format: "pdf", label: "PDF", helper: "Generate a board-ready management PDF." },
      { format: "json", label: "JSON", helper: "Export structured management dashboard data." },
    ],
  },
};

const ROLE_SEVERITY_POLICY: Record<UserRole, string> = {
  Admin: "All severities remain visible with full evidence.",
  "Security Analyst": "All severities remain visible for the selected security scope.",
  Developer: "All severities remain visible for the remediation scope, ordered by fix priority.",
  Auditor: "All severities remain visible with audit redaction applied to sensitive detail.",
  Management: "No raw issues; only aggregated risk and executive summaries are shown.",
};

const LANDING_HIGHLIGHTS = [
  "Codebase-only secure analysis designed to stay office-safe and audit-friendly.",
  "Parser, dataflow, dependency, and evidence-backed issues instead of loose pattern spam.",
  "Grounded remediation and report exports built for developers, security teams, and leadership.",
];

const LANDING_FEATURES: Array<{ title: string; body: string }> = [
  {
    title: "What It Does",
    body: "Scans source code, dependencies, secrets, and secure coding practices across a repo, then organizes the evidence into vulnerability, control, and fixes reports.",
  },
  {
    title: "Why Teams Use It",
    body: "It keeps the workflow grounded in real code context: file, line, evidence, validation basis, ownership, and release impact instead of generic analyzer output.",
  },
  {
    title: "What Makes It Different",
    body: "The platform is codebase-only by design, with deterministic evidence replay, fix verification hooks, portfolio history, and optional grounded AI assistance layered on top.",
  },
];

const LANDING_ADVANTAGES: Array<{ label: string; value: string }> = [
  { label: "Code Trust", value: "AST + flow-backed review" },
  { label: "Developer Fit", value: "Actionable fixes and exports" },
  { label: "Leadership View", value: "Readable board and control reporting" },
  { label: "Authenticity", value: "Evidence chain, replay, and verification" },
];

function sortFindings(items: VulnerabilityFinding[]): VulnerabilityFinding[] {
  return [...items].sort((a, b) => {
    const aRank = SEVERITY_ORDER.indexOf(a.severity);
    const bRank = SEVERITY_ORDER.indexOf(b.severity);
    if (aRank !== bRank) {
      return aRank - bRank;
    }
    if ((b.cvss_score || 0) !== (a.cvss_score || 0)) {
      return (b.cvss_score || 0) - (a.cvss_score || 0);
    }
    if (a.file_path !== b.file_path) {
      return a.file_path.localeCompare(b.file_path);
    }
    return (a.line_number || 0) - (b.line_number || 0);
  });
}

interface FileFindingAggregate {
  key: string;
  folder: string;
  counts: Record<Severity, number>;
  total: number;
}

interface ActiveScanSession {
  scanId: string;
  target: string;
  role: UserRole;
  status: ScanProgress["status"];
  stage: string;
  progress: number;
  message: string;
  currentFile?: string;
  startedAt: string;
  updatedAt: string;
  resultReady: boolean;
}

function aggregateFindingsByFile(findings: VulnerabilityFinding[]): FileFindingAggregate[] {
  const map = new Map<string, FileFindingAggregate>();
  for (const finding of findings) {
    const file = normalizeFindingPath(finding.file_path);
    if (!map.has(file)) {
      map.set(file, {
        key: file,
        folder: folderFromFindingPath(file),
        counts: { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 },
        total: 0,
      });
    }
    const row = map.get(file)!;
    row.counts[finding.severity] += 1;
    row.total += 1;
  }
  return [...map.values()].sort((a, b) => b.total - a.total);
}

function aggregateFindingsByFolder(findings: VulnerabilityFinding[]): FileFindingAggregate[] {
  const map = new Map<string, FileFindingAggregate>();
  for (const finding of findings) {
    const folder = folderFromFindingPath(finding.file_path);
    if (!map.has(folder)) {
      map.set(folder, {
        key: folder,
        folder,
        counts: { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 },
        total: 0,
      });
    }
    const row = map.get(folder)!;
    row.counts[finding.severity] += 1;
    row.total += 1;
  }
  return [...map.values()].sort((a, b) => b.total - a.total);
}

function normalizeSeverityLabel(value: unknown): Severity {
  const candidates: unknown[] = [];
  if (value && typeof value === "object") {
    const record = value as Record<string, unknown>;
    candidates.push(record.value, record.label, record.name, record.severity, record.level, record.text, record.display, record.code);
  }
  candidates.push(value);
  for (const candidate of candidates) {
    const text = String(candidate ?? "").trim().toLowerCase();
    if (!text) {
      continue;
    }
    const cleaned = text.replace(/severity[._-]?/g, "").replace(/[^a-z]+/g, " ").trim();
    if (/\bcritical\b|\berror\b/.test(cleaned)) return "Critical";
    if (/\bhigh\b/.test(cleaned)) return "High";
    if (/\bmedium\b|\bwarning\b/.test(cleaned)) return "Medium";
    if (/\blow\b|\bnote\b/.test(cleaned)) return "Low";
    if (/\binfo\b|\binformational\b/.test(cleaned)) return "Info";
  }
  return "Info";
}

function normalizeSeverityDistribution(value: unknown): Record<Severity, number> {
  const distribution: Record<Severity, number> = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return distribution;
  }
  for (const [key, rawCount] of Object.entries(value as Record<string, unknown>)) {
    const severity = normalizeSeverityLabel(key);
    const count = Number(rawCount);
    if (!Number.isFinite(count) || count <= 0) {
      continue;
    }
    distribution[severity] += count;
  }
  return distribution;
}

function aggregateSeverityDistribution(findings: VulnerabilityFinding[]): Record<Severity, number> {
  return findings.reduce<Record<Severity, number>>(
    (acc, finding) => {
      const severity = normalizeSeverityLabel((finding as unknown as Record<string, unknown>).severity);
      acc[severity] += 1;
      return acc;
    },
    { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 },
  );
}

type SeverityBreakdownInstance = {
  file_path: string;
  line_number: number;
  location: string;
  module?: string;
};

type SeverityBreakdownGroup = {
  severity: Severity;
  title: string;
  cwe: string;
  owasp: string;
  count: number;
  group_count?: number;
  modules: string[];
  instances: SeverityBreakdownInstance[];
};

type SeverityBreakdownSeverity = {
  severity: Severity;
  count: number;
  group_count: number;
  groups: SeverityBreakdownGroup[];
};

function normalizeSeverityBreakdownGroups(value: unknown): SeverityBreakdownSeverity[] {
  if (!Array.isArray(value)) {
    return [];
  }

  return value
    .map((entry) => {
      const record = entry as Record<string, unknown>;
      const severity = normalizeSeverityLabel(record.severity);
      const groups = Array.isArray(record.groups)
        ? record.groups
            .map((group) => {
              const item = group as Record<string, unknown>;
              const instances = Array.isArray(item.instances)
                ? item.instances
                    .map((instance) => {
                      const inst = instance as Record<string, unknown>;
                      const filePath = String(inst.file_path || inst.file || "unknown");
                      const lineNumber = Number(inst.line_number || inst.line || 1);
                      return {
                        file_path: filePath,
                        line_number: lineNumber,
                        location: String(inst.location || `${filePath}:${lineNumber}`),
                        module: String(inst.module || "").trim() || undefined,
                      };
                    })
                    .filter((inst) => inst.file_path)
                : [];
              return {
                severity,
                title: String(item.title || item.vulnerability_title || item.issue || "Issue"),
                cwe: String(item.cwe || item.cwe_id || "N/A"),
                owasp: String(item.owasp || item.owasp_mapping || "N/A"),
                count: Number(item.count || instances.length || 0),
                group_count: Number(item.group_count || 0),
                modules: Array.isArray(item.modules) ? item.modules.map((module) => String(module)).filter(Boolean) : [],
                instances,
              };
            })
            .filter((group) => group.title)
        : [];
      const count = Number(record.count || groups.reduce((total, group) => total + Number(group.count || 0), 0));
      const groupCount = Number(record.group_count || groups.length);
      return {
        severity,
        count,
        group_count: groupCount,
        groups: groups.sort((left, right) => Number(right.count || 0) - Number(left.count || 0) || left.title.localeCompare(right.title)),
      };
    })
    .filter((entry) => entry.groups.length > 0)
    .sort((left, right) => SEVERITY_ORDER.indexOf(left.severity) - SEVERITY_ORDER.indexOf(right.severity));
}

function aggregateSeverityFromBreakdown(groups: SeverityBreakdownSeverity[]): Record<Severity, number> {
  return groups.reduce<Record<Severity, number>>(
    (acc, group) => {
      acc[group.severity] += Number(group.count || 0);
      return acc;
    },
    { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 },
  );
}

function fileNameFromPath(value: string): string {
  const normalized = String(value || "").replaceAll("\\", "/");
  const parts = normalized.split("/").filter(Boolean);
  return parts.length ? parts[parts.length - 1] : normalized || "unknown";
}

function normalizeFindingPath(value: string): string {
  return String(value || "").replaceAll("\\", "/");
}

function buildScanStatusLine(payload: { stage: string; message: string; currentFile?: string }): string {
  const filePart = payload.currentFile ? ` | ${payload.currentFile}` : "";
  return `${payload.stage}${filePart} | ${payload.message}`;
}

function folderFromFindingPath(value: string): string {
  const normalized = normalizeFindingPath(value);
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

function normalizeToolEntry(tool: string, info: ToolchainStatusEntry): ToolchainStatusEntry {
  const execution = info.execution
    ? {
        attempted: Boolean(info.execution.attempted),
        status: String(info.execution.status || "pending"),
        duration_ms: Number(info.execution.duration_ms || 0),
        findings_count: Number(info.execution.findings_count || 0),
        errors: Array.isArray(info.execution.errors) ? info.execution.errors.map((item) => String(item)) : [],
      }
    : undefined;
  return {
    ...info,
    name: info.name || tool,
    display_name: info.display_name || tool,
    description: info.description || "No description provided.",
    category: info.category || "Uncategorized",
    target_modes: Array.isArray(info.target_modes) ? info.target_modes : [],
    vulnerability_classes: Array.isArray(info.vulnerability_classes) ? info.vulnerability_classes : [],
    homepage: info.homepage || "",
    selected: Boolean(info.selected),
    runner_available: Boolean(info.runner_available),
    integrated: Boolean(info.integrated),
    recommended_command: info.recommended_command || info.command,
    execution,
  };
}

function buildCoverageMatrix(entries: ToolchainStatusEntry[]): Array<{ vulnerabilityClass: string; tools: string[] }> {
  const matrix = new Map<string, Set<string>>();
  for (const entry of entries) {
    if (!entry.selected) {
      continue;
    }
    for (const item of entry.vulnerability_classes || []) {
      if (!matrix.has(item)) {
        matrix.set(item, new Set<string>());
      }
      matrix.get(item)!.add(entry.display_name || entry.name);
    }
  }

  return [...matrix.entries()]
    .map(([vulnerabilityClass, tools]) => ({
      vulnerabilityClass,
      tools: [...tools].sort((a, b) => a.localeCompare(b)),
    }))
    .sort((a, b) => a.vulnerabilityClass.localeCompare(b.vulnerabilityClass));
}

function inferToolProfiles(tool: {
  name: string;
  category: string;
  target_modes: string[];
  scan_profiles?: ToolScanProfile[];
}): ToolScanProfile[] {
  const explicit = (tool.scan_profiles || []).filter((profile): profile is ToolScanProfile => profile === "codebase");
  if (explicit.length > 0) {
    return ["codebase"];
  }
  const modes = new Set(tool.target_modes || []);
  if (modes.has("codebase") || modes.has("remote-codebase")) {
    return ["codebase"];
  }
  return [];
}

function roleDrilldownSummary(role: UserRole): string {
  const item = ROLE_DRILLDOWN.find((entry) => entry.role === role);
  if (!item) {
    return "";
  }
  return `${item.purpose} ${item.drillDownUse}`;
}

function enterpriseStatusClass(status: string | undefined): string {
  if (status === "ready") {
    return "enterprise-ready";
  }
  if (status === "warning") {
    return "enterprise-warning";
  }
  return "enterprise-blocked";
}

function formatPercent(value: number | undefined): string {
  const normalized = Number(value || 0);
  return `${normalized.toFixed(2)}%`;
}

function formatDuration(seconds: number): string {
  const safe = Math.max(0, Math.floor(seconds));
  const hh = Math.floor(safe / 3600);
  const mm = Math.floor((safe % 3600) / 60);
  const ss = safe % 60;
  if (hh > 0) {
    return `${hh}h ${mm}m ${ss}s`;
  }
  if (mm > 0) {
    return `${mm}m ${ss}s`;
  }
  return `${ss}s`;
}

function resolveProfileCompliance(scan: ScanView | null): ProfileComplianceReport | null {
  if (!scan) {
    return null;
  }
  const fromExisting = scan.report.existing_implementation_report.profile_compliance;
  if (fromExisting) {
    return fromExisting;
  }
  return scan.report.profile_compliance || null;
}

function resolveEnterpriseAssurance(scan: ScanView | null): EnterpriseAssuranceSummary | null {
  if (!scan) {
    return null;
  }
  return (
    scan.report.vulnerability_fixed_code_report.summary.enterprise_assurance ||
    scan.report.executive_summary.enterprise_assurance ||
    scan.report.existing_implementation_report.enterprise_assurance ||
    null
  );
}

function resolveToolchainExecution(scan: ScanView | null): ToolchainExecutionSummary | null {
  if (!scan) {
    return null;
  }
  return (
    scan.report.vulnerability_fixed_code_report.summary.toolchain_execution ||
    scan.report.executive_summary.toolchain_execution ||
    null
  );
}

function AppBrandIcon(props: {
  fallbackClassName: string;
  wrapperClassName?: string;
}): React.JSX.Element {
  return (
    <span className={props.wrapperClassName} aria-hidden="true">
      <BrandMark className={props.fallbackClassName} />
    </span>
  );
}

export default function App(): React.JSX.Element {
  const landingTransitionTimerRef = useRef<number | null>(null);
  const windowMenuRef = useRef<HTMLDivElement | null>(null);
  const [showLanding, setShowLanding] = useState<boolean>(true);
  const [landingTransition, setLandingTransition] = useState<"idle" | "to-app" | "to-landing">("idle");
  const [tab, setTab] = useState<AppTab>("dashboard");
  const [projectPath, setProjectPath] = useState("");
  const [threatModelPath, setThreatModelPath] = useState("");
  const [threatModelFramework, setThreatModelFramework] = useState<ThreatModelFramework>("STRIDE");
  const [scanPreset, setScanPreset] = useState<ScanPreset>("standard");
  const [diffBaseRef, setDiffBaseRef] = useState("");
  const [diffHeadRef, setDiffHeadRef] = useState("");
  const [changedFilesManifestPath, setChangedFilesManifestPath] = useState("");
  const [showScmOptions, setShowScmOptions] = useState(false);
  const [role, setRole] = useState<UserRole>("Security Analyst");
  const roleRef = useRef<UserRole>("Security Analyst");
  const [scanSessions, setScanSessions] = useState<Record<string, ActiveScanSession>>({});
  const [activeScanId, setActiveScanId] = useState("");
  const [scanStatus, setScanStatus] = useState<ScanProgress["status"]>("completed");
  const [statusText, setStatusText] = useState("Ready");
  const [progress, setProgress] = useState(0);
  const [progressHeartbeatTs, setProgressHeartbeatTs] = useState<number>(Date.now());
  const [lastProgressUpdateTs, setLastProgressUpdateTs] = useState<number>(Date.now());
  const [lastCompletedScanId, setLastCompletedScanId] = useState("");
  const [scan, setScan] = useState<ScanView | null>(null);
  const [baselineScan, setBaselineScan] = useState<ScanView | null>(null);
  const [threatModel, setThreatModel] = useState<ThreatModelResult | null>(null);
  const [threatModelStatus, setThreatModelStatus] = useState("Ready");
  const [isThreatModeling, setIsThreatModeling] = useState(false);
  const [lastThreatModelHtml, setLastThreatModelHtml] = useState("");
  const [lastThreatModelJson, setLastThreatModelJson] = useState("");
  const [lastThreatModelMermaid, setLastThreatModelMermaid] = useState("");
  const [history, setHistory] = useState<ScanHistoryItem[]>([]);
  const [portfolioSummary, setPortfolioSummary] = useState<PortfolioSummary | null>(null);
  const [audits, setAudits] = useState<AuditLogEntry[]>([]);
  const [reportHistory, setReportHistory] = useState<ReportHistoryItem[]>([]);
  const [selectedReportPaths, setSelectedReportPaths] = useState<Set<string>>(new Set());
  const [helpGuideMarkdown, setHelpGuideMarkdown] = useState<string>("");
  const [helpGuideMarkdownPath, setHelpGuideMarkdownPath] = useState<string>("");
  const [helpGuideHtmlPath, setHelpGuideHtmlPath] = useState<string>("");
  const [helpGuidePdfPath, setHelpGuidePdfPath] = useState<string>("");
  const [helpSearchText, setHelpSearchText] = useState<string>("");
  const [lastExport, setLastExport] = useState("");
  const [isExporting, setIsExporting] = useState(false);
  const [vulnerabilityReportStyle, setVulnerabilityReportStyle] = useState<ReportStyle>("classic");
  const [reportPreviewSrc, setReportPreviewSrc] = useState("");
  const [previewReportType, setPreviewReportType] = useState<ExportType | "">("");
  const [isPreviewLoading, setIsPreviewLoading] = useState(false);
  const [dashboardSection, setDashboardSection] = useState<DashboardSection>("overview");
  const [existingSection, setExistingSection] = useState<ExistingSection>("summary");
  const [vulnerabilitySection, setVulnerabilitySection] = useState<VulnerabilitySection>("queue");
  const [complianceSection, setComplianceSection] = useState<ComplianceSection>("profile");
  const [historySection, setHistorySection] = useState<HistorySection>("scans");
  const [toolSection, setToolSection] = useState<ToolManagerSection>("codebase");
  const [scanLogs, setScanLogs] = useState<string[]>([]);
  const [severityFilter, setSeverityFilter] = useState<Severity | "All">("All");
  const [findingScope, setFindingScope] = useState<FindingScope>("all");
  const [findingGroupMode, setFindingGroupMode] = useState<FindingGroupMode>("none");
  const [searchText, setSearchText] = useState("");
  const [selectedFindingId, setSelectedFindingId] = useState("");
  const [toolCatalog, setToolCatalog] = useState<ToolCatalogItem[]>([]);
  const [toolSearchText, setToolSearchText] = useState("");
  const [toolBusyKey, setToolBusyKey] = useState("");
  const [toolActionLogs, setToolActionLogs] = useState<string[]>([]);
  const [toolAuthConfig, setToolAuthConfig] = useState<ToolManagerAuthConfig | null>(null);
  const [toolAuthToken, setToolAuthToken] = useState("");
  const [toolOwnerEmail, setToolOwnerEmail] = useState("");
  const [toolOwnerOtp, setToolOwnerOtp] = useState("");
  const [toolOwnerMfa, setToolOwnerMfa] = useState("");
  const [toolAuthBusy, setToolAuthBusy] = useState(false);
  const [toolOtpRequested, setToolOtpRequested] = useState(false);
  const [showOwnerAccessPanel, setShowOwnerAccessPanel] = useState(false);
  const [activeWindowMenu, setActiveWindowMenu] = useState<WindowMenuKey | null>(null);
  const roleCaps = useMemo(() => ROLE_CAPABILITIES[role], [role]);
  const selectedRoleExport = useMemo(() => ROLE_EXPORT_PRESETS[role], [role]);
  const toolAuthEnabled = Boolean(toolAuthConfig?.enabled);
  const toolSessionValid = !toolAuthEnabled || Boolean(toolAuthToken);
  const toolAuthOtpRequired = Boolean(toolAuthConfig?.otpRequired);
  const toolAuthTotpOnly = toolAuthConfig?.authMode === "totp_only";
  const canOpenOwnerLogin = role === "Admin" || role === "Security Analyst";
  const isToolManagerVisible = !toolAuthEnabled || toolSessionValid;
  const roleMatchesScan = true;
  const visibleTabs = useMemo(
    () => TABS.filter((item) => item.key !== "tools" || isToolManagerVisible),
    [isToolManagerVisible],
  );

  const findings = useMemo(() => {
    if (!scan) {
      return [];
    }
    return sortFindings(scan.report.vulnerability_fixed_code_report.findings || []);
  }, [scan]);

  const baselineFindingIds = useMemo(() => {
    const ids = new Set<string>();
    if (!baselineScan) {
      return ids;
    }
    for (const item of baselineScan.report.vulnerability_fixed_code_report.findings || []) {
      ids.add(item.finding_uid);
    }
    return ids;
  }, [baselineScan]);

  const filteredFindings = useMemo(() => {
    const query = searchText.trim().toLowerCase();
    return findings.filter((item) => {
      if (severityFilter !== "All" && item.severity !== severityFilter) {
        return false;
      }
      if (findingScope === "new" && baselineFindingIds.has(item.finding_uid)) {
        return false;
      }
      if (
        findingScope === "changed" &&
        !item.git_diff_file_changed &&
        !item.git_diff_line_changed
      ) {
        return false;
      }
      if (!query) {
        return true;
      }
      const text = [
        item.vulnerability_title,
        item.vulnerability_type || "",
        item.file_path,
        item.cwe_id,
        item.owasp_mapping,
        item.code_owner || "",
        item.affected_module || "",
      ]
        .join(" ")
        .toLowerCase();
      return text.includes(query);
    });
  }, [findings, searchText, severityFilter, findingScope, baselineFindingIds]);

  const groupedFilteredFindings = useMemo(() => {
    if (findingGroupMode === "none") {
      return [{ key: "All Findings", items: filteredFindings }];
    }
    const groups = new Map<string, VulnerabilityFinding[]>();
    for (const item of filteredFindings) {
      const key =
        findingGroupMode === "module"
          ? item.affected_module || folderFromFindingPath(item.file_path)
          : item.code_owner || "Unassigned";
      const bucket = groups.get(key) || [];
      bucket.push(item);
      groups.set(key, bucket);
    }
    return [...groups.entries()]
      .sort((a, b) => a[0].localeCompare(b[0]))
      .map(([key, items]) => ({ key, items }));
  }, [filteredFindings, findingGroupMode]);

  const affectedFiles = useMemo(() => aggregateFindingsByFile(findings), [findings]);
  const affectedFolders = useMemo(() => aggregateFindingsByFolder(findings), [findings]);
  const profileCompliance = useMemo(() => resolveProfileCompliance(scan), [scan]);
  const enterpriseAssurance = useMemo(() => resolveEnterpriseAssurance(scan), [scan]);
  const toolchainExecution = useMemo(() => resolveToolchainExecution(scan), [scan]);
  const toolchainEntries = useMemo<ToolchainStatusEntry[]>(() => {
    if (!scan) {
      return [];
    }
    const entries = Object.entries(scan.report.vulnerability_fixed_code_report.toolchain_status || {})
      .filter(([tool]) => ACTIVE_CODEBASE_TOOLS.has(String(tool).trim().toLowerCase()))
      .map(([tool, info]) => normalizeToolEntry(tool, info));
    entries.sort((a, b) => {
      const selectedDelta = Number(Boolean(b.selected)) - Number(Boolean(a.selected));
      if (selectedDelta !== 0) {
        return selectedDelta;
      }
      const readyDelta = Number(Boolean(b.available)) - Number(Boolean(a.available));
      if (readyDelta !== 0) {
        return readyDelta;
      }
      return (a.display_name || a.name).localeCompare(b.display_name || b.name);
    });
    return entries;
  }, [scan]);
  const toolCoverage = useMemo(() => buildCoverageMatrix(toolchainEntries), [toolchainEntries]);
  const toolRows = useMemo(() => {
    return toolCatalog
      .filter((tool) => ACTIVE_CODEBASE_TOOLS.has(String(tool.name || "").trim().toLowerCase()))
      .map((tool) => {
      const status = toolchainEntries.find((item) => item.name === tool.name);
      const hostStatus: ToolchainStatusEntry | null =
        typeof tool.host_available === "boolean"
          ? {
              name: tool.name,
              available: Boolean(tool.host_available),
              command: tool.host_command || tool.command,
              source: tool.host_source || "unknown",
              message: tool.host_message || "",
            }
          : null;
      return {
        ...tool,
        scan_profiles: inferToolProfiles(tool),
        status: status || hostStatus,
      };
      });
  }, [toolCatalog, toolchainEntries]);
  const activeToolProfile = useMemo<ToolScanProfile>(() => "codebase", []);
  const filteredToolRows = useMemo(() => {
    const query = toolSearchText.trim().toLowerCase();
    return toolRows
      .filter((row) => row.scan_profiles.includes(activeToolProfile))
      .filter((row) => {
        if (!query) {
          return true;
        }
        const text = [
          row.display_name,
          row.name,
          row.category,
          ...(row.vulnerability_classes || []),
          ...(row.scan_profiles || []),
        ]
          .join(" ")
          .toLowerCase();
        return text.includes(query);
      })
      .sort((a, b) => {
        const readyDelta = Number(Boolean(b.status?.available)) - Number(Boolean(a.status?.available));
        if (readyDelta !== 0) {
          return readyDelta;
        }
        const integratedDelta = Number(Boolean(b.integrated)) - Number(Boolean(a.integrated));
        if (integratedDelta !== 0) {
          return integratedDelta;
        }
        return a.display_name.localeCompare(b.display_name);
      });
  }, [toolRows, activeToolProfile, toolSearchText]);
  const toolProfileStats = useMemo(() => {
    const stats: Record<ToolScanProfile, { total: number; ready: number; integrated: number }> = {
      codebase: { total: 0, ready: 0, integrated: 0 },
    };
    for (const row of toolRows) {
      for (const profile of row.scan_profiles) {
        if (!stats[profile]) {
          continue;
        }
        stats[profile].total += 1;
        if (row.status?.available) {
          stats[profile].ready += 1;
        }
        if (row.integrated) {
          stats[profile].integrated += 1;
        }
      }
    }
    return stats;
  }, [toolRows]);

  const selectedFinding = useMemo(() => {
    if (filteredFindings.length === 0) {
      return null;
    }
    const picked = filteredFindings.find((item) => item.finding_uid === selectedFindingId);
    return picked || filteredFindings[0];
  }, [filteredFindings, selectedFindingId]);

  const activeScanSessions = useMemo(
    () =>
      Object.values(scanSessions).sort(
        (a, b) => new Date(b.updatedAt).getTime() - new Date(a.updatedAt).getTime(),
      ),
    [scanSessions],
  );

  const selectedActiveSession = useMemo(() => {
    if (activeScanId && scanSessions[activeScanId]) {
      return scanSessions[activeScanId];
    }
    return activeScanSessions[0] || null;
  }, [activeScanId, activeScanSessions, scanSessions]);

  const isScanning = useMemo(
    () => activeScanSessions.some((item) => item.status === "running" || item.status === "paused"),
    [activeScanSessions],
  );

  const hasScmContext = useMemo(
    () => Boolean(diffBaseRef.trim() || diffHeadRef.trim() || changedFilesManifestPath.trim()),
    [diffBaseRef, diffHeadRef, changedFilesManifestPath],
  );

  const secondsSinceProgressUpdate = useMemo(
    () => Math.max(0, Math.floor((progressHeartbeatTs - lastProgressUpdateTs) / 1000)),
    [progressHeartbeatTs, lastProgressUpdateTs],
  );

  const selectedSessionElapsed = useMemo(() => {
    if (!selectedActiveSession) {
      return 0;
    }
    const started = new Date(selectedActiveSession.startedAt).getTime();
    if (Number.isNaN(started)) {
      return 0;
    }
    return Math.max(0, Math.floor((progressHeartbeatTs - started) / 1000));
  }, [selectedActiveSession, progressHeartbeatTs]);

  const isFinalizingPhase = useMemo(
    () =>
      scanStatus === "running" &&
      progress >= 95 &&
      progress < 100 &&
      secondsSinceProgressUpdate >= 8,
    [scanStatus, progress, secondsSinceProgressUpdate],
  );

  const displayProgress = useMemo(() => {
    if (!isFinalizingPhase) {
      return progress;
    }
    const pulse = ((Math.sin(progressHeartbeatTs / 850) + 1) / 2) * 1.6;
    return Math.min(99.4, Math.max(95, progress) + pulse);
  }, [isFinalizingPhase, progress, progressHeartbeatTs]);

  const clearLandingTimer = () => {
    if (landingTransitionTimerRef.current) {
      window.clearTimeout(landingTransitionTimerRef.current);
      landingTransitionTimerRef.current = null;
    }
  };

  const openPlatform = () => {
    if (landingTransition !== "idle") {
      return;
    }
    clearLandingTimer();
    setLandingTransition("to-app");
    landingTransitionTimerRef.current = window.setTimeout(() => {
      setShowLanding(false);
      setLandingTransition("idle");
      landingTransitionTimerRef.current = null;
    }, 820);
  };

  const reopenLanding = () => {
    if (landingTransition !== "idle") {
      return;
    }
    clearLandingTimer();
    setShowLanding(true);
    setLandingTransition("to-landing");
    landingTransitionTimerRef.current = window.setTimeout(() => {
      setLandingTransition("idle");
      landingTransitionTimerRef.current = null;
    }, 820);
  };

  useEffect(() => {
    roleRef.current = role;
  }, [role]);

  useEffect(() => {
    const dispose = window.codeSentinelX.onScanProgress((payload) => {
      const nowTs = Date.now();
      const now = new Date().toISOString();
      setScanSessions((previous) => {
        const current = previous[payload.scanId];
        return {
          ...previous,
          [payload.scanId]: {
            scanId: payload.scanId,
            target: current?.target || "Unknown target",
            role: current?.role || "Security Analyst",
            status: payload.status,
            stage: payload.stage,
            progress: payload.progress,
            message: payload.message,
            currentFile: payload.currentFile,
            startedAt: current?.startedAt || now,
            updatedAt: now,
            resultReady: current?.resultReady || payload.status === "completed",
          },
        };
      });
      setActiveScanId((current) => (payload.stage === "queued" || !current ? payload.scanId : current));
      if (!activeScanId || activeScanId === payload.scanId) {
        setScanStatus(payload.status);
        setStatusText(buildScanStatusLine(payload));
        setProgress(payload.progress);
      }
      setLastProgressUpdateTs(nowTs);
      if (payload.status === "completed") {
        setLastCompletedScanId(payload.scanId);
        window.codeSentinelX
          .getScanById(payload.scanId, roleRef.current)
          .then((result) => {
            if (result) {
              setScan((current) => {
                if (!current || current.scanId === result.scanId) {
                  return result;
                }
                return current;
              });
            }
          })
          .catch(() => undefined);
      }
      const time = new Date().toLocaleTimeString();
      const line = `[${time}] ${payload.scanId.slice(0, 8)} | ${buildScanStatusLine(payload)}`;
      setScanLogs((previous) => [line, ...previous].slice(0, 300));
    });
    return () => dispose();
  }, [activeScanId]);

  useEffect(() => {
    const timer = window.setInterval(() => setProgressHeartbeatTs(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, []);

  useEffect(() => {
    return () => clearLandingTimer();
  }, []);

  useEffect(() => {
    if (!activeWindowMenu) {
      return;
    }
    const onPointerDown = (event: MouseEvent): void => {
      if (!windowMenuRef.current?.contains(event.target as Node)) {
        setActiveWindowMenu(null);
      }
    };
    const onKeyDown = (event: KeyboardEvent): void => {
      if (event.key === "Escape") {
        setActiveWindowMenu(null);
      }
    };
    window.addEventListener("mousedown", onPointerDown);
    window.addEventListener("keydown", onKeyDown);
    return () => {
      window.removeEventListener("mousedown", onPointerDown);
      window.removeEventListener("keydown", onKeyDown);
    };
  }, [activeWindowMenu]);

  useEffect(() => {
    loadHistory().catch((error) => setStatusText(`History load failed: ${String(error)}`));
    loadAudits().catch(() => undefined);
    loadReportHistory().catch(() => undefined);
    loadHelpGuide().catch(() => undefined);
    loadToolAuthConfig()
      .then((config) => {
        if (!config.enabled || config.sessionValid) {
          return loadTools();
        }
        return Promise.resolve();
      })
      .catch((error) => setStatusText(`Analyzer Catalog auth load failed: ${String(error)}`));
  }, []);

  useEffect(() => {
    if (!scan) {
      setBaselineScan(null);
      return;
    }
    const sameProjectHistory = history
      .filter((item) => item.projectPath === scan.projectPath && item.scanId !== scan.scanId)
      .sort((a, b) => new Date(b.completedAt).getTime() - new Date(a.completedAt).getTime());
    const olderBaseline =
      sameProjectHistory.find((item) => new Date(item.completedAt).getTime() < new Date(scan.completedAt).getTime()) ||
      sameProjectHistory[0];
    if (!olderBaseline) {
      setBaselineScan(null);
      return;
    }
    window.codeSentinelX
      .getScanById(olderBaseline.scanId, role)
      .then((value) => setBaselineScan(value))
      .catch(() => setBaselineScan(null));
  }, [scan, history, role]);

  useEffect(() => {
    if (!scan?.scanId) {
      return;
    }
    window.codeSentinelX
      .getScanById(scan.scanId, role)
      .then((projected) => {
        if (projected) {
          setScan((current) => (current?.scanId === projected.scanId ? projected : current));
        }
      })
      .catch(() => undefined);
  }, [role, scan?.scanId]);

  useEffect(() => {
    if (selectedFinding && selectedFinding.finding_uid !== selectedFindingId) {
      setSelectedFindingId(selectedFinding.finding_uid);
    }
  }, [selectedFinding, selectedFindingId]);

  useEffect(() => {
    if (!selectedActiveSession) {
      return;
    }
    if (!activeScanId) {
      setActiveScanId(selectedActiveSession.scanId);
    }
    setScanStatus(selectedActiveSession.status);
    setProgress(selectedActiveSession.progress);
    setLastProgressUpdateTs(Date.now());
    setStatusText(buildScanStatusLine(selectedActiveSession));
  }, [activeScanId, selectedActiveSession]);

  useEffect(() => {
    if (!isToolManagerVisible && tab === "tools") {
      setTab("dashboard");
    }
    if ((isToolManagerVisible || !canOpenOwnerLogin) && showOwnerAccessPanel) {
      setShowOwnerAccessPanel(false);
    }
  }, [isToolManagerVisible, tab, showOwnerAccessPanel, canOpenOwnerLogin]);

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent): void => {
      const target = event.target as HTMLElement | null;
      const tagName = (target?.tagName || "").toLowerCase();
      const isEditable = target?.isContentEditable || tagName === "input" || tagName === "textarea" || tagName === "select";
      if (isEditable) {
        return;
      }

      if (event.altKey && /^\d$/.test(event.key)) {
        const index = Number(event.key) - 1;
        const targetTab = visibleTabs[index];
        if (targetTab) {
          event.preventDefault();
          setTab(targetTab.key);
        }
        return;
      }

      if (event.altKey || event.ctrlKey || event.metaKey || !/^[1-9]$/.test(event.key)) {
        return;
      }

      const index = Number(event.key) - 1;
      if (tab === "dashboard") {
        const items: DashboardSection[] = ["overview", "toolchain", "assets", "operations"];
        if (items[index]) {
          event.preventDefault();
          setDashboardSection(items[index]);
        }
        return;
      }
      if (tab === "existing") {
        const items: ExistingSection[] = ["summary", "controls", "compliance"];
        if (items[index]) {
          event.preventDefault();
          setExistingSection(items[index]);
        }
        return;
      }
      if (tab === "vulnerabilities") {
        const items: VulnerabilitySection[] = ["queue", "detail"];
        if (items[index]) {
          event.preventDefault();
          setVulnerabilitySection(items[index]);
        }
        return;
      }
      if (tab === "compliance") {
        const items: ComplianceSection[] = ["profile", "matrix", "actions"];
        if (items[index]) {
          event.preventDefault();
          setComplianceSection(items[index]);
        }
        return;
      }
      if (tab === "history") {
        const items: HistorySection[] = ["scans", "audits", "reports"];
        if (items[index]) {
          event.preventDefault();
          setHistorySection(items[index]);
        }
        return;
      }
      if (tab === "tools") {
        const items: ToolManagerSection[] = ["codebase", "roles", "policy"];
        if (items[index]) {
          event.preventDefault();
          setToolSection(items[index]);
        }
      }
    };

    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [tab, visibleTabs]);

  useEffect(() => {
    if (tab !== "tools") {
      return;
    }
    loadToolAuthConfig()
      .then(async (config) => {
        if (!config.enabled || toolAuthToken) {
          await loadTools();
        }
      })
      .catch((error) => setStatusText(`Analyzer Catalog init failed: ${String(error)}`));
  }, [tab, toolAuthToken]);

  const loadHistory = async (): Promise<void> => {
    const [items, summary] = await Promise.all([window.codeSentinelX.getScanHistory(), window.codeSentinelX.getPortfolioSummary()]);
    setHistory(items);
    setPortfolioSummary(summary);
    if (items.length > 0) {
      const latest = [...items].sort(
        (a, b) => new Date(b.completedAt).getTime() - new Date(a.completedAt).getTime(),
      )[0];
      if (latest?.scanId) {
        setLastCompletedScanId(latest.scanId);
      }
    }
  };

  const loadAudits = async (scanId?: string): Promise<void> => {
    const items = await window.codeSentinelX.listAuditLogs(scanId);
    setAudits(items);
  };

  const loadReportHistory = async (): Promise<void> => {
    const items = await window.codeSentinelX.getReportHistory();
    setReportHistory(items);
    setSelectedReportPaths(new Set());
  };

  const loadHelpGuide = async (): Promise<void> => {
    const payload = await window.codeSentinelX.getHelpGuide();
    setHelpGuideMarkdown(payload.markdown || "");
    setHelpGuideMarkdownPath(payload.markdownPath || "");
    setHelpGuideHtmlPath(payload.htmlPath || "");
    setHelpGuidePdfPath(payload.pdfPath || "");
  };

  const helpSections = useMemo(() => parseHelpGuideSections(helpGuideMarkdown), [helpGuideMarkdown]);
  const filteredHelpSections = useMemo(() => {
    const query = helpSearchText.trim().toLowerCase();
    if (!query) {
      return helpSections;
    }
    return helpSections.filter((section) => {
      if (section.title.toLowerCase().includes(query)) {
        return true;
      }
      return section.lines.some((line) => line.toLowerCase().includes(query));
    });
  }, [helpSections, helpSearchText]);

  const toggleReportSelection = (fullPath: string): void => {
    setSelectedReportPaths((prev) => {
      const next = new Set(prev);
      if (next.has(fullPath)) {
        next.delete(fullPath);
      } else {
        next.add(fullPath);
      }
      return next;
    });
  };

  const selectAllReports = (): void => {
    setSelectedReportPaths(new Set(reportHistory.map((item) => item.fullPath)));
  };

  const clearReportSelection = (): void => {
    setSelectedReportPaths(new Set());
  };

  const deleteSelectedReports = async (): Promise<void> => {
    if (selectedReportPaths.size === 0) {
      setStatusText("No reports selected.");
      return;
    }
    const confirmed = window.confirm(`Delete ${selectedReportPaths.size} selected report file(s)?`);
    if (!confirmed) {
      return;
    }
    const result = await window.codeSentinelX.deleteReportHistory({ paths: Array.from(selectedReportPaths) });
    await Promise.all([loadReportHistory(), loadAudits()]);
    setStatusText(`Reports cleanup completed. Deleted: ${result.deleted}, Failed: ${result.failed}`);
  };

  const deleteAllReports = async (): Promise<void> => {
    if (!reportHistory.length) {
      setStatusText("No reports to delete.");
      return;
    }
    const confirmed = window.confirm(`Delete all ${reportHistory.length} exported report file(s)?`);
    if (!confirmed) {
      return;
    }
    const result = await window.codeSentinelX.deleteReportHistory({ all: true });
    await Promise.all([loadReportHistory(), loadAudits()]);
    setStatusText(`All reports cleanup completed. Deleted: ${result.deleted}, Failed: ${result.failed}`);
  };

  const loadToolAuthConfig = async (tokenOverride?: string): Promise<ToolManagerAuthConfig> => {
    const token = tokenOverride !== undefined ? tokenOverride : toolAuthToken;
    const config = await window.codeSentinelX.getToolAccessConfig({ authToken: token || undefined });
    setToolAuthConfig(config);
    return config;
  };

  const loadTools = async (): Promise<void> => {
    try {
      const tools = await window.codeSentinelX.listTools({ authToken: toolAuthToken || undefined });
      setToolCatalog(tools);
    } catch (error) {
      const message = String(error);
      if (message.toLowerCase().includes("tool manager access denied") || message.toLowerCase().includes("session expired")) {
        setToolCatalog([]);
      } else {
        throw error;
      }
    }
  };

  const browseProject = async (): Promise<void> => {
    const picked = await window.codeSentinelX.pickProjectFolder();
    if (picked) {
      setProjectPath(picked);
    }
  };

  const browseThreatModelProject = async (): Promise<void> => {
    const picked = await window.codeSentinelX.pickProjectFolder();
    if (picked) {
      setThreatModelPath(picked);
    }
  };

  const createThreatModel = async (): Promise<void> => {
    const targetPath = threatModelPath.trim();
    if (!targetPath) {
      setThreatModelStatus("Select a project file or folder before creating a threat model.");
      return;
    }
    setIsThreatModeling(true);
    setThreatModelStatus(`Analyzing codebase for ${threatModelFramework} threat model...`);
    try {
      const result = await window.codeSentinelX.createThreatModel({
        projectPath: targetPath,
        requestedBy: "local-user",
        framework: threatModelFramework,
      });
      setThreatModel(result);
      setLastThreatModelHtml(result.htmlPath);
      setLastThreatModelJson(result.jsonPath);
      setLastThreatModelMermaid(result.mermaidPath);
      const threatIds = result.report.threats.map((threat, index) => threat.threat_id || `TM-${index + 1}`).join(", ");
      setThreatModelStatus(
        `${result.report.framework} threat model completed: ${result.report.summary.threats} threats from ${result.report.summary.source_files_analyzed} source files. Threat IDs: ${threatIds || "none"}.`,
      );
    } catch (error) {
      setThreatModelStatus(error instanceof Error ? error.message : String(error));
    } finally {
      setIsThreatModeling(false);
    }
  };

  const runScan = async (): Promise<void> => {
    if (!roleCaps.canRunScan) {
      setStatusText(`Role ${role} does not have permission to start scans.`);
      return;
    }
    const targetPath = projectPath.trim();
    if (!targetPath) {
      setStatusText("Select a project file or folder before scanning.");
      return;
    }
    const roleForScan = role;
    const presetForScan = scanPreset;
    setScanStatus("running");
    setProgress(0);
    setLastProgressUpdateTs(Date.now());
    setStatusText("Submitting secure code analysis...");
    const time = new Date().toLocaleTimeString();
    setScanLogs((previous) => [`[${time}] queued | ${targetPath}`, ...previous].slice(0, 300));
    try {
      const scmContext: ScmDiffContext | undefined =
        diffBaseRef.trim() || diffHeadRef.trim() || changedFilesManifestPath.trim()
          ? {
              diffBaseRef: diffBaseRef.trim() || undefined,
              diffHeadRef: diffHeadRef.trim() || undefined,
              changedFilesFile: changedFilesManifestPath.trim() || undefined,
            }
          : undefined;
      const result = await window.codeSentinelX.startScan({
        projectPath: targetPath,
        requestedBy: "local-user",
        role: roleForScan,
        scanPreset: presetForScan,
        scmContext,
      });
      let loadedResult = result;
      try {
        const fromStore = await window.codeSentinelX.getScanById(result.scanId, role);
        if (fromStore) {
          loadedResult = fromStore;
        }
      } catch {
        // Keep the startScan result if store refresh is temporarily unavailable.
      }
      const now = new Date().toISOString();
      setScanSessions((previous) => {
        const current = previous[loadedResult.scanId];
        return {
          ...previous,
          [loadedResult.scanId]: {
            scanId: loadedResult.scanId,
            target: targetPath,
            role: roleForScan,
            status: "completed",
            stage: "completed",
            progress: 100,
            message: "Scan completed",
            currentFile: current?.currentFile,
            startedAt: current?.startedAt || now,
            updatedAt: now,
            resultReady: true,
          },
        };
      });
      if (loadedResult.role && loadedResult.role !== roleRef.current) {
        roleRef.current = loadedResult.role;
        setRole(loadedResult.role);
      }
      setScan(loadedResult);
      setActiveScanId(loadedResult.scanId);
      setLastCompletedScanId(loadedResult.scanId);
      setStatusText("Scan completed");
      setScanStatus("completed");
      setProgress(100);
      setLastProgressUpdateTs(Date.now());
      setSelectedFindingId("");
      await Promise.all([loadHistory(), loadAudits(loadedResult.scanId)]);
    } catch (error) {
      const message = String(error);
      if (message.toLowerCase().includes("scan stopped by user")) {
        setStatusText("Scan stopped by user.");
        setScanStatus("stopped");
      } else {
        setStatusText(`Scan failed: ${message}`);
        setScanStatus("failed");
      }
    }
  };

  const pauseScan = async (): Promise<void> => {
    if (!roleCaps.canRunScan) {
      setStatusText(`Role ${role} does not have permission to control scans.`);
      return;
    }
    if (!selectedActiveSession) {
      setStatusText("No active scan found to pause.");
      return;
    }
    const result = await window.codeSentinelX.pauseScan(selectedActiveSession.scanId);
    setStatusText(result.message);
    if (result.success) {
      setScanStatus("paused");
      setScanSessions((previous) => ({
        ...previous,
        [result.scanId]: {
          ...(previous[result.scanId] || {
            scanId: result.scanId,
            target: "Unknown target",
            role,
            startedAt: new Date().toISOString(),
            updatedAt: new Date().toISOString(),
            resultReady: false,
          }),
          status: "paused",
          stage: "paused",
          message: result.message,
          updatedAt: new Date().toISOString(),
        },
      }));
    }
  };

  const resumeScan = async (): Promise<void> => {
    if (!roleCaps.canRunScan) {
      setStatusText(`Role ${role} does not have permission to control scans.`);
      return;
    }
    if (!selectedActiveSession) {
      setStatusText("No active scan found to resume.");
      return;
    }
    const result = await window.codeSentinelX.resumeScan(selectedActiveSession.scanId);
    setStatusText(result.message);
    if (result.success) {
      setScanStatus("running");
      setScanSessions((previous) => ({
        ...previous,
        [result.scanId]: {
          ...(previous[result.scanId] || {
            scanId: result.scanId,
            target: "Unknown target",
            role,
            startedAt: new Date().toISOString(),
            updatedAt: new Date().toISOString(),
            resultReady: false,
          }),
          status: "running",
          stage: "running",
          message: result.message,
          updatedAt: new Date().toISOString(),
        },
      }));
    }
  };

  const stopScan = async (): Promise<void> => {
    if (!roleCaps.canRunScan) {
      setStatusText(`Role ${role} does not have permission to control scans.`);
      return;
    }
    if (!selectedActiveSession) {
      setStatusText("No active scan found to stop.");
      return;
    }
    const result = await window.codeSentinelX.stopScan(selectedActiveSession.scanId);
    setStatusText(result.message);
    if (result.success) {
      setScanStatus("stopped");
      setScanSessions((previous) => ({
        ...previous,
        [result.scanId]: {
          ...(previous[result.scanId] || {
            scanId: result.scanId,
            target: "Unknown target",
            role,
            startedAt: new Date().toISOString(),
            updatedAt: new Date().toISOString(),
            resultReady: false,
          }),
          status: "stopped",
          stage: "stopped",
          message: result.message,
          updatedAt: new Date().toISOString(),
        },
      }));
    }
  };

  const openScan = async (scanId: string, projectionRole: UserRole = role): Promise<void> => {
    const result = await window.codeSentinelX.getScanById(scanId, projectionRole);
    if (!result) {
      setStatusText(`Scan ${scanId} not found.`);
      return;
    }
    if (result.role && result.role !== roleRef.current) {
      roleRef.current = result.role;
      setRole(result.role);
    }
    setScan(result);
    setLastCompletedScanId(scanId);
    setStatusText(`Loaded scan ${scanId.slice(0, 8)}`);
    setProgress(100);
    setSelectedFindingId("");
    await loadAudits(scanId);
  };

  const reopenLastCompletedScan = async (): Promise<void> => {
    if (!lastCompletedScanId) {
      setStatusText("No completed scan available to reopen.");
      return;
    }
    await openScan(lastCompletedScanId);
  };

  const markReviewed = async (findingId: string): Promise<void> => {
    if (!roleCaps.canReviewFindings) {
      setStatusText(`Role ${role} cannot mark issues as reviewed.`);
      return;
    }
    if (!scan) {
      return;
    }
    const updated = await window.codeSentinelX.markReviewed({
      scanId: scan.scanId,
      findingId,
      actor: "local-user",
      role,
    });
    if (updated) {
      setScan(updated);
      setStatusText("Issue marked as reviewed.");
      await loadAudits(scan.scanId);
    }
  };

  const copyPatch = async (findingId: string): Promise<void> => {
    if (!roleCaps.canCopyFixes) {
      setStatusText(`Role ${role} cannot copy remediation patches.`);
      return;
    }
    if (!scan) {
      return;
    }
    const patch = await window.codeSentinelX.generatePatch({ scanId: scan.scanId, findingId });
    if (!patch) {
      setStatusText("No patch preview available for this issue.");
      return;
    }
    await navigator.clipboard.writeText(patch);
    setStatusText("Patch copied to clipboard.");
  };

  const copyFixCode = async (text: string): Promise<void> => {
    if (!roleCaps.canCopyFixes) {
      setStatusText(`Role ${role} cannot copy fix snippets.`);
      return;
    }
    if (!text) {
      return;
    }
    await navigator.clipboard.writeText(text);
    setStatusText("Fix code copied to clipboard.");
  };

  const exportReport = async (format: ExportFormat): Promise<void> => {
    if (!scan) {
      setStatusText("No scan loaded for export.");
      return;
    }
    const managementContext: ManagementReportContext | undefined =
      selectedRoleExport.reportType === "management"
        ? {
            portfolioSummary,
            scanHistory: [
              ...history
                .filter((item) => item.projectPath === scan.projectPath)
                .sort((left, right) => new Date(left.completedAt).getTime() - new Date(right.completedAt).getTime())
                .map((item) => ({
                  scanId: item.scanId,
                  projectPath: item.projectPath,
                  startedAt: item.startedAt,
                  completedAt: item.completedAt,
                  riskScore: item.riskScore,
                  totalFindings: item.totalFindings,
                  criticalFindings: item.criticalFindings,
                  highFindings: item.highFindings,
                  mediumFindings: item.mediumFindings,
                  lowFindings: item.lowFindings,
                  infoFindings: item.infoFindings,
                  reviewedFindings: item.reviewedFindings,
                  suppressedCount: item.suppressedCount,
                })),
              {
                scanId: scan.scanId,
                projectPath: scan.projectPath,
                startedAt: scan.startedAt,
                completedAt: scan.completedAt,
                riskScore: Number(scan.report.executive_summary.risk_score || 0),
                totalFindings: Number(scan.report.executive_summary.deduplicated_vulnerabilities || scan.report.executive_summary.total_vulnerabilities || 0),
                criticalFindings: Number(scan.report.executive_summary.severity_distribution?.Critical || 0),
                highFindings: Number(scan.report.executive_summary.severity_distribution?.High || 0),
                mediumFindings: Number(scan.report.executive_summary.severity_distribution?.Medium || 0),
                lowFindings: Number(scan.report.executive_summary.severity_distribution?.Low || 0),
                infoFindings: Number(scan.report.executive_summary.severity_distribution?.Info || 0),
                reviewedFindings: Number(scan.report.vulnerability_fixed_code_report.summary.reviewed_findings || 0),
                suppressedCount: Number(scan.report.false_positive_report?.candidate_count || scan.report.vulnerability_fixed_code_report.summary.suppressed_by_policy || 0),
              },
            ],
          }
        : undefined;
    setIsExporting(true);
    const reportType = selectedRoleExport.reportType;
    const styleLabel = reportType === "vulnerability" ? ` (${vulnerabilityReportStyle})` : "";
    setStatusText(`Preparing ${selectedRoleExport.title} ${format.toUpperCase()} export...`);
    await new Promise<void>((resolve) => window.requestAnimationFrame(() => resolve()));
    try {
      const output = await window.codeSentinelX.exportReport({
        scanId: scan.scanId,
        role,
        reportType,
        format,
        reportStyle: reportType === "vulnerability" ? vulnerabilityReportStyle : undefined,
        managementContext,
      });
      setLastExport(output);
      setStatusText(`Exported ${selectedRoleExport.title} as ${format}${styleLabel}`);
      await Promise.all([loadAudits(scan.scanId), loadReportHistory()]);
    } finally {
      setIsExporting(false);
    }
  };

  const previewReport = async (): Promise<void> => {
    if (!scan) {
      setStatusText("Run a scan before previewing reports.");
      return;
    }
    const managementContext: ManagementReportContext | undefined =
      selectedRoleExport.reportType === "management"
        ? {
            portfolioSummary,
            scanHistory: [
              ...history
                .filter((item) => item.projectPath === scan.projectPath)
                .sort((left, right) => new Date(left.completedAt).getTime() - new Date(right.completedAt).getTime())
                .map((item) => ({
                  scanId: item.scanId,
                  projectPath: item.projectPath,
                  startedAt: item.startedAt,
                  completedAt: item.completedAt,
                  riskScore: item.riskScore,
                  totalFindings: item.totalFindings,
                  criticalFindings: item.criticalFindings,
                  highFindings: item.highFindings,
                  mediumFindings: item.mediumFindings,
                  lowFindings: item.lowFindings,
                  infoFindings: item.infoFindings,
                  reviewedFindings: item.reviewedFindings,
                  suppressedCount: item.suppressedCount,
                })),
              {
                scanId: scan.scanId,
                projectPath: scan.projectPath,
                startedAt: scan.startedAt,
                completedAt: scan.completedAt,
                riskScore: Number(scan.report.executive_summary.risk_score || 0),
                totalFindings: Number(scan.report.executive_summary.deduplicated_vulnerabilities || scan.report.executive_summary.total_vulnerabilities || 0),
                criticalFindings: Number(scan.report.executive_summary.severity_distribution?.Critical || 0),
                highFindings: Number(scan.report.executive_summary.severity_distribution?.High || 0),
                mediumFindings: Number(scan.report.executive_summary.severity_distribution?.Medium || 0),
                lowFindings: Number(scan.report.executive_summary.severity_distribution?.Low || 0),
                infoFindings: Number(scan.report.executive_summary.severity_distribution?.Info || 0),
                reviewedFindings: Number(scan.report.vulnerability_fixed_code_report.summary.reviewed_findings || 0),
                suppressedCount: Number(scan.report.false_positive_report?.candidate_count || scan.report.vulnerability_fixed_code_report.summary.suppressed_by_policy || 0),
              },
            ],
          }
        : undefined;
    setIsPreviewLoading(true);
    const reportType = selectedRoleExport.reportType;
    setPreviewReportType(reportType);
    try {
      const previewSrc = await window.codeSentinelX.renderReportHtml({
        scanId: scan.scanId,
        role,
        reportType,
        reportStyle: reportType === "vulnerability" ? vulnerabilityReportStyle : undefined,
        managementContext,
      });
      setReportPreviewSrc(previewSrc);
      const styleLabel = reportType === "vulnerability" ? ` (${vulnerabilityReportStyle})` : "";
      setStatusText(`Loaded ${selectedRoleExport.title} preview${styleLabel}.`);
      setTab("dashboard");
    } catch (error) {
      setPreviewReportType("");
      setReportPreviewSrc("");
      setStatusText(`Failed to render preview: ${String(error)}`);
    } finally {
      setIsPreviewLoading(false);
    }
  };

  const closePreview = (): void => {
      setReportPreviewSrc("");
      setPreviewReportType("");
      setIsPreviewLoading(false);
  };

  const closeWindowMenu = (): void => {
    setActiveWindowMenu(null);
  };

  const toggleWindowMenu = (menuKey: WindowMenuKey): void => {
    setActiveWindowMenu((current) => (current === menuKey ? null : menuKey));
  };

  const openLastExport = async (): Promise<void> => {
    if (!lastExport) {
      setStatusText("No export path available yet.");
      return;
    }
    const result = await window.codeSentinelX.openPath(lastExport);
    if (result && result.trim().length > 0) {
      setStatusText(`Could not open exported file: ${result}`);
      return;
    }
    setStatusText("Opened exported report.");
  };

  const openLastExportFolder = async (): Promise<void> => {
    if (!lastExport) {
      setStatusText("No export path available yet.");
      return;
    }
    const folderPath = lastExport.replace(/[\\/][^\\/]+$/, "");
    const result = await window.codeSentinelX.openPath(folderPath);
    if (result && result.trim().length > 0) {
      setStatusText(`Could not open export folder: ${result}`);
      return;
    }
    setStatusText("Opened export folder.");
  };

  const copyProjectFolderPath = async (): Promise<void> => {
    if (!projectPath.trim()) {
      setStatusText("No project file or folder selected yet.");
      return;
    }
    await navigator.clipboard.writeText(projectPath.trim());
    setStatusText("Project folder copied to clipboard.");
  };

  const resetFindingFilters = (): void => {
    setSearchText("");
    setSeverityFilter("All");
    setFindingScope("all");
    setFindingGroupMode("none");
    setStatusText("Issue filters cleared.");
  };

  const openPrimaryDashboardView = (): void => {
    setTab("dashboard");
    setDashboardSection("overview");
    setStatusText("Opened Code Risk Overview.");
  };

  const openPrimaryFindingView = (): void => {
    setTab("vulnerabilities");
    setVulnerabilitySection("queue");
    setStatusText("Opened Code Findings.");
  };

  const openPolicyView = (): void => {
    setTab("tools");
    setToolSection("policy");
    setStatusText("Opened analyzer execution policy.");
  };

  const showShortcutHelp = (): void => {
    setStatusText("Shortcuts: Alt+1..7 switch tabs. Number keys switch visible sub-sections.");
  };

  const openHelpTab = (): void => {
    setTab("help");
    setStatusText("Opened Help.");
  };

  const openHelpHtml = async (): Promise<void> => {
    let htmlPath = helpGuideHtmlPath;
    if (!htmlPath) {
      htmlPath = await window.codeSentinelX.ensureHelpHtml();
      setHelpGuideHtmlPath(htmlPath);
    }
    const result = await window.codeSentinelX.openPath(htmlPath);
    if (result && result.trim()) {
      setStatusText(`Could not open Help HTML: ${result}`);
      return;
    }
    setStatusText("Opened Help HTML guide.");
  };

  const openHelpPdf = async (): Promise<void> => {
    let pdfPath = helpGuidePdfPath;
    if (!pdfPath) {
      pdfPath = await window.codeSentinelX.ensureHelpPdf();
      setHelpGuidePdfPath(pdfPath);
    }
    const result = await window.codeSentinelX.openPath(pdfPath);
    if (result && result.trim()) {
      setStatusText(`Could not open Help PDF: ${result}`);
      return;
    }
    setStatusText("Opened Help PDF.");
  };

  const openHelpMarkdownFile = async (): Promise<void> => {
    if (!helpGuideMarkdownPath) {
      setStatusText("Help markdown path unavailable.");
      return;
    }
    const result = await window.codeSentinelX.openPath(helpGuideMarkdownPath);
    if (result && result.trim()) {
      setStatusText(`Could not open Help markdown: ${result}`);
      return;
    }
    setStatusText("Opened Help markdown file.");
  };

  const scrollHelpToSection = (sectionId: string): void => {
    const target = document.getElementById(sectionId);
    if (!target) {
      return;
    }
    target.scrollIntoView({ behavior: "smooth", block: "start" });
  };

  const windowMenuActions = useMemo<
    Record<WindowMenuKey, Array<{ label: string; disabled?: boolean; onSelect: () => void | Promise<void> }>>
  >(
    () => ({
      file: [
        { label: "Browse File or Folder", onSelect: browseProject },
        { label: "Run Canonical Scan", disabled: !projectPath.trim() || !roleCaps.canRunScan, onSelect: runScan },
        { label: "Open Last Export", disabled: !lastExport, onSelect: openLastExport },
        { label: "Open Export Folder", disabled: !lastExport, onSelect: openLastExportFolder },
      ],
      edit: [
        { label: "Copy Project Path", disabled: !projectPath.trim(), onSelect: copyProjectFolderPath },
        { label: "Clear Search", disabled: !searchText.trim(), onSelect: () => setSearchText("") },
        { label: "Reset Finding Filters", onSelect: resetFindingFilters },
      ],
      view: [
        { label: "Code Risk Overview", onSelect: openPrimaryDashboardView },
        { label: "Code Findings", onSelect: openPrimaryFindingView },
        { label: "Secure Coding Practices", onSelect: () => { setTab("existing"); setExistingSection("summary"); setStatusText("Opened Secure Coding Practices."); } },
        { label: "Compliance", onSelect: () => { setTab("compliance"); setComplianceSection("profile"); setStatusText("Opened Compliance."); } },
        { label: "Scan History", onSelect: () => { setTab("history"); setHistorySection("scans"); setStatusText("Opened Scan History."); } },
        { label: "Help Center", onSelect: openHelpTab },
      ],
      window: [
        { label: "Minimize", onSelect: () => window.codeSentinelX.minimizeWindow() },
        { label: "Maximize / Restore", onSelect: async () => { await window.codeSentinelX.toggleMaximizeWindow(); } },
        { label: "Close Window", onSelect: () => window.codeSentinelX.closeWindow() },
      ],
      help: [
        { label: "Help Center", onSelect: openHelpTab },
        { label: "Open Help HTML", onSelect: openHelpHtml },
        { label: "Open Help PDF", onSelect: openHelpPdf },
        { label: "Open Help Markdown", disabled: !helpGuideMarkdownPath, onSelect: openHelpMarkdownFile },
        { label: "Show Keyboard Shortcuts", onSelect: showShortcutHelp },
        { label: `Preview ${selectedRoleExport.title}`, disabled: !scan || !roleMatchesScan, onSelect: () => previewReport() },
        { label: "Analyzer Policy", onSelect: openPolicyView },
        { label: "Welcome Screen", onSelect: reopenLanding },
      ],
    }),
    [
      lastExport,
      helpGuideHtmlPath,
      helpGuideMarkdownPath,
      openHelpHtml,
      openHelpTab,
      openLastExport,
      openLastExportFolder,
      openHelpMarkdownFile,
      openHelpPdf,
      openHelpTab,
      projectPath,
      reopenLanding,
      previewReport,
      roleMatchesScan,
      roleCaps.canRunScan,
      runScan,
      scan,
      searchText,
      selectedRoleExport,
    ],
  );

  const requestToolManagerOtp = async (): Promise<void> => {
    if (!toolAuthConfig?.enabled) {
      setStatusText("Analyzer Catalog owner lock is not enabled.");
      return;
    }
    if (!toolOwnerEmail.trim()) {
      setStatusText("Enter owner email before requesting OTP.");
      return;
    }
    setToolAuthBusy(true);
    try {
      const result = (await window.codeSentinelX.requestToolAccessOtp({
        email: toolOwnerEmail.trim(),
      })) as ToolManagerOtpResult;
      if (result.success) {
        setToolOtpRequested(true);
      } else {
        setToolOtpRequested(false);
      }
      setStatusText(result.message);
      await loadAudits();
    } catch (error) {
      setStatusText(`OTP request failed: ${String(error)}`);
    } finally {
      setToolAuthBusy(false);
    }
  };

  const verifyToolManagerOtp = async (): Promise<void> => {
    if (!toolAuthConfig?.enabled) {
      setStatusText("Analyzer Catalog owner lock is not enabled.");
      return;
    }
    if (!toolOwnerEmail.trim()) {
      setStatusText("Enter owner email.");
      return;
    }
    if (toolAuthOtpRequired && !toolOwnerOtp.trim()) {
      setStatusText("Enter OTP code.");
      return;
    }
    if (toolAuthConfig.mfaRequired && !toolOwnerMfa.trim()) {
      setStatusText("MFA code is required.");
      return;
    }
    setToolAuthBusy(true);
    try {
      const result = (await window.codeSentinelX.verifyToolAccess({
        email: toolOwnerEmail.trim(),
        otp: toolAuthOtpRequired ? toolOwnerOtp.trim() : "",
        mfaCode: toolOwnerMfa.trim() || undefined,
      })) as ToolManagerVerifyResult;

      if (!result.success || !result.authToken) {
        setStatusText(result.message);
        return;
      }

      setToolAuthToken(result.authToken);
      setToolOwnerOtp("");
      setToolOwnerMfa("");
      setToolOtpRequested(false);
      const config = await loadToolAuthConfig(result.authToken);
      if (!config.enabled || config.sessionValid) {
        await loadTools();
      }
      setStatusText(result.message);
      await loadAudits();
    } catch (error) {
      setStatusText(`Analyzer Catalog verification failed: ${String(error)}`);
    } finally {
      setToolAuthBusy(false);
    }
  };

  const logoutToolManagerSession = async (): Promise<void> => {
    setToolAuthBusy(true);
    try {
      const result = await window.codeSentinelX.logoutToolAccess({ authToken: toolAuthToken || undefined });
      setToolAuthToken("");
      setToolCatalog([]);
      setToolOwnerOtp("");
      setToolOwnerMfa("");
      setToolOtpRequested(false);
      await loadToolAuthConfig("");
      setStatusText(result.message || "Analyzer Catalog session ended.");
      await loadAudits();
    } catch (error) {
      setStatusText(`Logout failed: ${String(error)}`);
    } finally {
      setToolAuthBusy(false);
    }
  };

  const renderOwnerAccessPanel = (): React.JSX.Element => {
    return (
      <section className="panel stack-gap">
        <div className="tool-auth-panel">
          <h3>Analyzer Catalog Owner Access</h3>
          <p className="muted-text">
            Owner-only mode is enabled. Only the configured email can unlock Analyzer Catalog operations.
          </p>
          <p className="muted-text">{toolAuthConfig?.message || ""}</p>

          <div className="tool-auth-grid">
            <input
              value={toolOwnerEmail}
              onChange={(event) => setToolOwnerEmail(event.target.value)}
              placeholder="Owner email"
              autoComplete="off"
              disabled={toolAuthBusy}
            />
            {toolAuthOtpRequired ? (
              <div className="button-row">
                <button type="button" onClick={requestToolManagerOtp} disabled={toolAuthBusy || !toolAuthConfig?.smtpConfigured}>
                  {toolAuthBusy ? "Sending..." : "Send OTP"}
                </button>
              </div>
            ) : (
              <div className="muted-text">TOTP-only mode: use your authenticator app code.</div>
            )}
          </div>
          <div className="tool-auth-grid">
            {toolAuthOtpRequired && (
              <input
                value={toolOwnerOtp}
                onChange={(event) => setToolOwnerOtp(event.target.value)}
                placeholder="6-digit OTP"
                autoComplete="one-time-code"
                disabled={toolAuthBusy}
              />
            )}
            <input
              value={toolOwnerMfa}
              onChange={(event) => setToolOwnerMfa(event.target.value)}
              placeholder={toolAuthTotpOnly ? "Authenticator code (required)" : toolAuthConfig?.mfaRequired ? "MFA code (required)" : "MFA code (optional)"}
              autoComplete="one-time-code"
              disabled={toolAuthBusy}
            />
          </div>

          <div className="button-row">
            <button
              type="button"
              onClick={verifyToolManagerOtp}
              disabled={
                toolAuthBusy ||
                !toolOwnerEmail.trim() ||
                (toolAuthOtpRequired && (!toolOtpRequested || !toolOwnerOtp.trim())) ||
                (Boolean(toolAuthConfig?.mfaRequired) && !toolOwnerMfa.trim())
              }
            >
              {toolAuthBusy ? "Verifying..." : "Verify and Unlock"}
            </button>
            <button type="button" onClick={() => setShowOwnerAccessPanel(false)} disabled={toolAuthBusy}>
              Close
            </button>
          </div>
        </div>
      </section>
    );
  };

  const resetLocalStateCache = async (): Promise<void> => {
    if (!roleCaps.canProvisionTools) {
      setStatusText(`Role ${role} cannot reset local state/cache.`);
      return;
    }
    if (toolAuthEnabled && !toolAuthToken) {
      setStatusText("Analyzer Catalog owner authentication is required.");
      return;
    }
    if (isScanning) {
      setStatusText("Stop the active scan before resetting local state/cache.");
      return;
    }

    const confirmed = window.confirm(
      "Reset local state/cache?\n\nThis will clear scan history, audit state, exported preview cache, and tool-run cache for this app profile.",
    );
    if (!confirmed) {
      return;
    }

    const key = "reset-local-state-cache";
    setToolBusyKey(key);
    try {
      const result = (await window.codeSentinelX.resetLocalStateCache({
        authToken: toolAuthToken || undefined,
      })) as ResetLocalStateCacheResult;
      const stamp = new Date().toLocaleTimeString();
      const coreLine = result.coreWarmup
        ? ` | coreWarmup=${result.coreWarmup.ready}/${result.coreWarmup.total} ready, missing=${result.coreWarmup.missing}`
        : "";
      const backupLine = result.storeBackupPath ? ` | backup=${result.storeBackupPath}` : "";
      const cacheLine = result.toolchainCachePath ? ` | cache=${result.toolchainCachePath}` : "";
      const line = `[${stamp}] reset local-state-cache => ${result.success ? "SUCCESS" : "FAILED"} | ${result.message}${coreLine}${cacheLine}${backupLine}`;
      setToolActionLogs((previous) => [line, ...previous].slice(0, 300));

      setScan(null);
      setScanSessions({});
      setActiveScanId("");
      setLastCompletedScanId("");
      setSelectedFindingId("");
      setThreatModel(null);
      setThreatModelStatus("Ready");
      setThreatModelPath("");
      setLastThreatModelHtml("");
      setLastThreatModelJson("");
      setLastThreatModelMermaid("");
      setProgress(0);
      setLastExport("");
      setReportPreviewSrc("");
      setPreviewReportType("");
      setScanLogs([]);

      const seedMessage = result.seedMessage ? ` ${result.seedMessage}` : "";
      setStatusText(`${result.message}${seedMessage}`);
      await Promise.all([loadHistory(), loadAudits(), loadTools()]);
    } catch (error) {
      setStatusText(`Reset failed: ${String(error)}`);
    } finally {
      setToolBusyKey("");
    }
  };

  const renderDashboard = (): React.JSX.Element => {
    if (!scan) {
      return <EmptyState text="Run a scan to view dashboard metrics." />;
    }
    const summary = scan.report.executive_summary;
    const vulnSummary = scan.report.vulnerability_fixed_code_report.summary;
    const activeProjectionRole = scan.role || role;
    const vulnerabilityFindingsSummary = ((scan.report as unknown as Record<string, unknown>).vulnerability_findings as { summary?: Record<string, unknown> } | undefined)?.summary;
    const dashboardSummary = summary;
    const dashboardVulnSummary = vulnSummary;
    const dashboardSummaryAny = dashboardSummary as Record<string, any>;
    const dashboardVulnSummaryAny = dashboardVulnSummary as Record<string, any>;
    const summaryRecord = summary as unknown as Record<string, unknown>;
    const vulnSummaryRecord = vulnSummary as unknown as Record<string, unknown>;
    const managementSummaryRecord = ((summary as Record<string, unknown>).management_summary ||
      (vulnSummary as Record<string, unknown>).management_summary ||
      {}) as Record<string, unknown>;
    const vulnerabilityFindingsSummaryRecord = (vulnerabilityFindingsSummary || {}) as Record<string, unknown>;
    const managementSeverityBreakdown = normalizeSeverityBreakdownGroups(
      managementSummaryRecord.severity_breakdown_groups ||
        vulnerabilityFindingsSummaryRecord.severity_breakdown_groups ||
        vulnSummaryRecord.severity_breakdown_groups,
    );
    const executiveSeverityDistribution = normalizeSeverityDistribution(
      summaryRecord.severity_distribution_raw || summaryRecord.severity_distribution,
    );
    const managementSeverityDistribution = normalizeSeverityDistribution(
      managementSummaryRecord.severity_distribution_raw || managementSummaryRecord.severity_distribution,
    );
    const findingsSeverityDistributionFromSummary = normalizeSeverityDistribution(
      vulnerabilityFindingsSummaryRecord.severity_distribution_raw || vulnerabilityFindingsSummaryRecord.severity_distribution,
    );
    const fallbackSeverityDistribution = normalizeSeverityDistribution(vulnSummaryRecord.severity_distribution);
    const findingsSeverityDistribution = aggregateSeverityDistribution(findings);
    const severityBreakdownSeverityDistribution = aggregateSeverityFromBreakdown(managementSeverityBreakdown);
    const severityTotal = (distribution: Record<Severity, number> | undefined) =>
      Object.values(distribution || {}).reduce((total, value) => total + Number(value || 0), 0);
    const dashboardSeverityDistribution =
      activeProjectionRole === "Management"
        ? (severityTotal(managementSeverityDistribution) > 0
            ? managementSeverityDistribution
            : severityTotal(severityBreakdownSeverityDistribution) > 0
              ? severityBreakdownSeverityDistribution
              : severityTotal(executiveSeverityDistribution) > 0
                ? executiveSeverityDistribution
                : severityTotal(findingsSeverityDistributionFromSummary) > 0
                  ? findingsSeverityDistributionFromSummary
                  : severityTotal(fallbackSeverityDistribution) > 0
                    ? fallbackSeverityDistribution
                    : findingsSeverityDistribution)
        : (severityTotal(executiveSeverityDistribution) > 0
            ? executiveSeverityDistribution
            : severityTotal(findingsSeverityDistributionFromSummary) > 0
              ? findingsSeverityDistributionFromSummary
              : severityTotal(severityBreakdownSeverityDistribution) > 0
                ? severityBreakdownSeverityDistribution
                : severityTotal(fallbackSeverityDistribution) > 0
                  ? fallbackSeverityDistribution
                  : findingsSeverityDistribution);
    const positiveNumberOrFallback = (primary: unknown, fallback: number) => {
      const numeric = Number(primary);
      return Number.isFinite(numeric) && numeric > 0 ? numeric : fallback;
    };
    const dashboardOwaspCategories: Array<{ owasp_category: string; count: number }> =
      activeProjectionRole === "Management"
        ? ((managementSummaryRecord.top_owasp_categories ||
            vulnerabilityFindingsSummaryRecord.top_owasp_categories ||
            summary.top_owasp_categories ||
            []) as Array<{ owasp_category: string; count: number }>)
        : ((vulnSummary.top_owasp_categories || summary.top_owasp_categories || []) as Array<{ owasp_category: string; count: number }>);
    const dashboardAffectedModules: Array<{ module: string; count: number; critical: number; high: number }> =
      activeProjectionRole === "Management"
        ? ((managementSummaryRecord.affected_modules ||
            vulnerabilityFindingsSummaryRecord.affected_modules ||
            vulnSummary.affected_modules ||
            []) as Array<{ module: string; count: number; critical: number; high: number }>)
        : ((vulnSummary.affected_modules || []) as Array<{ module: string; count: number; critical: number; high: number }>);
    const dashboardActionPlan: string[] =
      activeProjectionRole === "Management"
        ? ((managementSummaryRecord.recommended_action_plan || summary.recommended_action_plan || []) as string[])
        : ((summary.recommended_action_plan || []) as string[]);

    return (
      <section className="panel stack-gap">
        <SubTabs
          tabs={[
            { key: "overview", label: "Overview", icon: "OV" },
            { key: "toolchain", label: "Analyzer Coverage", icon: "TL" },
            { key: "assets", label: "Assets", icon: "AS" },
            { key: "operations", label: "Operations", icon: "OP" },
          ]}
          active={dashboardSection}
          onChange={(value) => setDashboardSection(value as DashboardSection)}
        />

        {dashboardSection === "overview" && (
          <>
            <div className="metric-grid">
              <MetricCard label="Risk Score" value={`${summary.risk_score} (${summary.risk_rating})`} />
              <MetricCard label="Files Scanned" value={String(summary.files_scanned)} />
              <MetricCard
                label="Raw Findings"
                value={String(
                  activeProjectionRole === "Management"
                    ? positiveNumberOrFallback(
                        dashboardSummaryAny.total_findings,
                        positiveNumberOrFallback(
                          vulnerabilityFindingsSummaryRecord.total,
                          positiveNumberOrFallback(vulnerabilityFindingsSummaryRecord.raw_total, positiveNumberOrFallback(vulnSummary.total_findings, summary.total_vulnerabilities)),
                        ),
                      )
                    : summary.total_vulnerabilities,
                )}
              />
              <MetricCard
                label="Deduplicated Findings"
                value={String(
                  activeProjectionRole === "Management"
                    ? positiveNumberOrFallback(
                        dashboardSummaryAny.deduplicated_vulnerabilities,
                        positiveNumberOrFallback(
                          dashboardSummaryAny.total_findings,
                          positiveNumberOrFallback(vulnerabilityFindingsSummaryRecord.total, vulnSummary.total_findings),
                        ),
                      )
                    : vulnSummary.total_findings,
                )}
              />
              <MetricCard
                label="Open Findings"
                value={String(
                  activeProjectionRole === "Management"
                    ? positiveNumberOrFallback(
                        dashboardSummaryAny.active_risk_findings,
                        positiveNumberOrFallback(
                          dashboardSummaryAny.total_findings,
                          positiveNumberOrFallback(vulnerabilityFindingsSummaryRecord.total, positiveNumberOrFallback(vulnSummary.total_findings, 0)),
                        ),
                      )
                    : vulnSummary.open_findings ?? vulnSummary.total_findings,
                )}
              />
              <MetricCard
                label="Reviewed Findings"
                value={String(
                  activeProjectionRole === "Management"
                    ? positiveNumberOrFallback(
                        dashboardSummaryAny.deduplicated_vulnerabilities,
                        positiveNumberOrFallback(
                          dashboardSummaryAny.total_findings,
                          positiveNumberOrFallback(vulnerabilityFindingsSummaryRecord.total, positiveNumberOrFallback(vulnSummary.total_findings, 0)),
                        ),
                      )
                    : vulnSummary.reviewed_findings || 0,
                )}
              />
              <MetricCard
                label="Enterprise Status"
                value={(enterpriseAssurance?.status || "blocked").toUpperCase()}
              />
              <MetricCard label="Readiness Score" value={String(enterpriseAssurance?.readiness_score ?? 0)} />
              <MetricCard
                label="Required Tool Coverage"
                value={formatPercent(enterpriseAssurance?.required_tools_coverage_percent)}
              />
              <MetricCard label="Tool Success Rate" value={formatPercent(toolchainExecution?.success_rate_percent)} />
            </div>

            <div className="severity-strip">
              {SEVERITY_ORDER.map((severity) => (
                <article key={severity} className={`severity-card severity-${severity}`}>
                  <p>{severity}</p>
                  <h4>{dashboardSeverityDistribution?.[severity] || 0}</h4>
                </article>
              ))}
            </div>

              {activeProjectionRole === "Management" && managementSeverityBreakdown.length > 0 && (
                <div className="subpanel">
                  <h3>Severity Drilldown</h3>
                  <p className="muted-text">
                    Grouped by severity, vulnerability, and CWE. Expand a group to see the file and line instances behind the count.
                  </p>
                <div className="severity-breakdown-list">
                  {managementSeverityBreakdown.map((severityGroup) => (
                    <details key={severityGroup.severity} className="severity-breakdown-section" open={severityGroup.severity === "Critical"}>
                      <summary>
                        <span>{severityGroup.severity}</span>
                        <strong>{severityGroup.count}</strong>
                      </summary>
                      <div className="table-frame" style={{ marginTop: 12 }}>
                        <table className="simple-table severity-breakdown-table">
                          <thead>
                            <tr>
                              <th>Vulnerability</th>
                              <th>CWE</th>
                              <th>OWASP</th>
                              <th>Instances</th>
                              <th>Top File</th>
                              <th>Top Line</th>
                            </tr>
                          </thead>
                          <tbody>
                            {severityGroup.groups.map((group) => {
                              const topInstance = group.instances[0];
                              const topFile = topInstance ? fileNameFromPath(topInstance.file_path) : "N/A";
                              const topLine = topInstance?.line_number || "N/A";
                              return (
                                <tr key={`${severityGroup.severity}-${group.title}-${group.cwe}`}>
                                  <td>
                                    <details className="severity-breakdown-group">
                                      <summary>
                                        {group.title}
                                        <span className="severity-breakdown-count">{group.count}</span>
                                      </summary>
                                      <div className="severity-breakdown-instances">
                                        <table className="simple-table">
                                          <thead>
                                            <tr>
                                              <th>File Name</th>
                                              <th>File / Path</th>
                                              <th>Line</th>
                                              <th>Module</th>
                                            </tr>
                                          </thead>
                                          <tbody>
                                            {group.instances.map((instance) => (
                                              <tr key={`${severityGroup.severity}-${group.title}-${group.cwe}-${instance.location}`}>
                                                <td>{fileNameFromPath(instance.file_path)}</td>
                                                <td title={instance.file_path}>{instance.file_path}</td>
                                                <td>{instance.line_number}</td>
                                                <td>{instance.module || "root"}</td>
                                              </tr>
                                            ))}
                                          </tbody>
                                        </table>
                                      </div>
                                    </details>
                                  </td>
                                  <td>{group.cwe}</td>
                                  <td>{group.owasp}</td>
                                  <td>{group.count}</td>
                                  <td title={topInstance?.file_path || "N/A"}>{topFile}</td>
                                  <td>{topLine}</td>
                                </tr>
                              );
                            })}
                          </tbody>
                        </table>
                      </div>
                    </details>
                  ))}
                </div>
              </div>
            )}

            <div className="three-col">
              <div className="subpanel">
                <h3>Top OWASP Categories</h3>
                <table className="simple-table">
                  <thead>
                    <tr>
                      <th>OWASP Category</th>
                      <th>Count</th>
                    </tr>
                  </thead>
                  <tbody>
                    {dashboardOwaspCategories
                      .slice(0, 10)
                      .map((item) => (
                      <tr key={item.owasp_category}>
                        <td>{item.owasp_category}</td>
                        <td>{item.count}</td>
                      </tr>
                    ))}
                    {dashboardOwaspCategories.length === 0 && (
                      <tr>
                        <td colSpan={2}>No OWASP category data available.</td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>

              <div className="subpanel">
                <h3>Affected Modules</h3>
                <table className="simple-table">
                  <thead>
                    <tr>
                      <th>Module</th>
                      <th>Total</th>
                      <th>Critical</th>
                      <th>High</th>
                    </tr>
                  </thead>
                  <tbody>
                    {dashboardAffectedModules
                      .slice(0, 10)
                      .map((item) => (
                      <tr key={`${item.module}-${item.count}`}>
                        <td>{item.module}</td>
                        <td>{item.count}</td>
                        <td>{item.critical}</td>
                        <td>{item.high}</td>
                      </tr>
                    ))}
                    {dashboardAffectedModules.length === 0 && (
                      <tr>
                        <td colSpan={4}>No affected module data available.</td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>

              <div className="subpanel">
                <h3>Action Plan</h3>
                <ol className="action-list">
                  {dashboardActionPlan.slice(0, 7).map((item) => (
                    <li key={item}>{item}</li>
                  ))}
                  {dashboardActionPlan.length === 0 && <li>No action plan available.</li>}
                </ol>
              </div>
            </div>

            <div className="two-col">
              <div className="subpanel">
                <h3>Enterprise Readiness Verdict</h3>
                <p className={`enterprise-pill ${enterpriseStatusClass(enterpriseAssurance?.status)}`}>
                  {(enterpriseAssurance?.status || "blocked").toUpperCase()}
                </p>
                <table className="simple-table">
                  <tbody>
                    <tr>
                      <th>Score</th>
                      <td>{enterpriseAssurance?.readiness_score ?? 0}</td>
                    </tr>
                    <tr>
                      <th>Required Tools Ready</th>
                      <td>
                        {enterpriseAssurance?.required_tools_ready ?? 0}/{enterpriseAssurance?.required_tools_total ?? 0}
                      </td>
                    </tr>
                    <tr>
                      <th>Required Coverage</th>
                      <td>{formatPercent(enterpriseAssurance?.required_tools_coverage_percent)}</td>
                    </tr>
                    <tr>
                      <th>Tool Success Rate</th>
                      <td>{formatPercent(toolchainExecution?.success_rate_percent)}</td>
                    </tr>
                  </tbody>
                </table>
                {enterpriseAssurance?.recommendation && <p className="muted-text">{enterpriseAssurance.recommendation}</p>}
              </div>

              {((enterpriseAssurance?.blockers || []).length > 0 || (enterpriseAssurance?.advisories || []).length > 0) && (
                <div className="subpanel">
                  {(enterpriseAssurance?.blockers || []).length > 0 && (
                    <>
                      <h3>Enterprise Blockers</h3>
                      <ul className="action-list">
                        {(enterpriseAssurance?.blockers || []).slice(0, 12).map((item, index) => (
                          <li key={`${index}-${item}`}>{item}</li>
                        ))}
                      </ul>
                    </>
                  )}
                  {(enterpriseAssurance?.advisories || []).length > 0 && (
                    <>
                      <h3>Coverage Notes</h3>
                      <ul className="action-list">
                        {(enterpriseAssurance?.advisories || []).slice(0, 10).map((item, index) => (
                          <li key={`${index}-${item}`}>{item}</li>
                        ))}
                      </ul>
                    </>
                  )}
                </div>
              )}
            </div>
          </>
        )}

        {dashboardSection === "toolchain" && (
          <>
            <div className="metric-grid toolchain-metrics">
              <MetricCard
                label="Catalog Tools"
                value={String(toolchainExecution?.total_tools ?? toolchainEntries.length)}
              />
              <MetricCard
                label="Selected This Scan"
                value={String(toolchainExecution?.selected_tools ?? toolchainEntries.filter((item) => item.selected).length)}
              />
              <MetricCard
                label="Ready Tools"
                value={String(toolchainExecution?.available_tools ?? toolchainEntries.filter((item) => item.available).length)}
              />
              <MetricCard
                label="Integrated Parsers"
                value={String(
                  toolchainExecution?.integrated_tools ?? toolchainEntries.filter((item) => item.integrated).length,
                )}
              />
              <MetricCard label="Attempted Tools" value={String(toolchainExecution?.attempted_tools ?? 0)} />
              <MetricCard label="Successful Tools" value={String(toolchainExecution?.successful_tools ?? 0)} />
              <MetricCard label="Failed Tools" value={String(toolchainExecution?.failed_tools ?? 0)} />
              <MetricCard label="Tool Success Rate" value={formatPercent(toolchainExecution?.success_rate_percent)} />
              <MetricCard
                label="Local Scope"
                value="Codebase only"
              />
              <MetricCard
                label="Codebase-Capable"
                value={String(
                  toolchainEntries.filter((item) => {
                    const modes = item.target_modes || [];
                    return modes.includes("codebase") || modes.includes("remote-codebase");
                  }).length,
                )}
              />
            </div>

            <div className="two-col">
              <div className="subpanel">
                <h3>Analyzer Status and Coverage</h3>
                <div className="table-scroll">
                  <table className="simple-table toolchain-table">
                    <thead>
                      <tr>
                        <th>Tool</th>
                        <th>Selected</th>
                        <th>Available</th>
                        <th>Codebase Modes</th>
                        <th>Vulnerability Coverage</th>
                        <th>Category</th>
                        <th>Source</th>
                        <th>Execution</th>
                        <th>Duration (ms)</th>
                        <th>Findings</th>
                        <th>Status</th>
                      </tr>
                    </thead>
                    <tbody>
                      {toolchainEntries.map((entry) => (
                        <tr key={entry.name}>
                          <td>
                            <div className="tool-cell">
                              <span
                                className="tool-name-chip"
                                title={`${entry.description || "No description"}\n${
                                  entry.homepage ? `Homepage: ${entry.homepage}` : ""
                                }`}
                              >
                                {entry.display_name || entry.name}
                              </span>
                              <span className={`integration-pill ${entry.integrated ? "integration-on" : "integration-off"}`}>
                                {entry.integrated ? "Integrated" : "Catalog"}
                              </span>
                            </div>
                          </td>
                          <td>{entry.selected ? "Yes" : "No"}</td>
                          <td>{entry.available ? "Ready" : "Missing"}</td>
                          <td>
                            {(entry.target_modes || [])
                              .filter((item) => item === "codebase" || item === "remote-codebase")
                              .join(", ") || "codebase"}
                          </td>
                          <td>{(entry.vulnerability_classes || []).join(", ") || "-"}</td>
                          <td>{entry.category || "-"}</td>
                          <td>{entry.source || "-"}</td>
                          <td>{entry.execution?.status || (entry.selected ? "pending" : "not_selected")}</td>
                          <td>{entry.execution?.duration_ms ?? 0}</td>
                          <td>{entry.execution?.findings_count ?? 0}</td>
                          <td>{entry.message || "-"}</td>
                        </tr>
                      ))}
                      {toolchainEntries.length === 0 && (
                        <tr>
                          <td colSpan={11}>No analyzer data available.</td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </div>

              <div className="subpanel">
                <h3>Selected Analyzer Coverage Matrix</h3>
                <table className="simple-table">
                  <thead>
                    <tr>
                      <th>Vulnerability Class</th>
                      <th>Selected Tools</th>
                    </tr>
                  </thead>
                  <tbody>
                    {toolCoverage.map((row) => (
                      <tr key={row.vulnerabilityClass}>
                        <td>{row.vulnerabilityClass}</td>
                        <td>{row.tools.join(", ")}</td>
                      </tr>
                    ))}
                    {toolCoverage.length === 0 && (
                      <tr>
                        <td colSpan={2}>No selected tools with mapped vulnerability coverage yet.</td>
                      </tr>
                    )}
                  </tbody>
                </table>
                <p className="muted-text">
                  Hover tool names in the table for quick context about what each tool does.
                </p>
                <h4>Execution Failures</h4>
                <table className="simple-table">
                  <thead>
                    <tr>
                      <th>Tool</th>
                      <th>Status</th>
                      <th>Message</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(toolchainExecution?.failures || []).slice(0, 12).map((item) => (
                      <tr key={`${item.tool}-${item.status}`}>
                        <td>{item.tool}</td>
                        <td>{item.status}</td>
                        <td>{item.message || (item.errors || []).join("; ") || "-"}</td>
                      </tr>
                    ))}
                    {(toolchainExecution?.failures || []).length === 0 && (
                      <tr>
                        <td colSpan={3}>No execution failures recorded for selected tools.</td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          </>
        )}

        {dashboardSection === "assets" && (
          <div className="two-col">
            <div className="subpanel">
              <h3>Affected Files</h3>
              <table className="simple-table">
                <thead>
                  <tr>
                    <th>File</th>
                    <th>Folder</th>
                    <th>Critical</th>
                    <th>High</th>
                    <th>Total</th>
                  </tr>
                </thead>
                <tbody>
                  {affectedFiles.slice(0, 12).map((item) => (
                    <tr key={item.key}>
                      <td>{item.key}</td>
                      <td>{item.folder}</td>
                      <td>{item.counts.Critical}</td>
                      <td>{item.counts.High}</td>
                      <td>{item.total}</td>
                    </tr>
                  ))}
                  {affectedFiles.length === 0 && (
                    <tr>
                      <td colSpan={5}>No affected files found.</td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>

            <div className="subpanel">
              <h3>Affected Folders</h3>
              <table className="simple-table">
                <thead>
                  <tr>
                    <th>Folder</th>
                    <th>Critical</th>
                    <th>High</th>
                    <th>Medium</th>
                    <th>Total</th>
                  </tr>
                </thead>
                <tbody>
                  {affectedFolders.slice(0, 12).map((item) => (
                    <tr key={item.key}>
                      <td>{item.folder}</td>
                      <td>{item.counts.Critical}</td>
                      <td>{item.counts.High}</td>
                      <td>{item.counts.Medium}</td>
                      <td>{item.total}</td>
                    </tr>
                  ))}
                  {affectedFolders.length === 0 && (
                    <tr>
                      <td colSpan={5}>No affected folders found.</td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {dashboardSection === "operations" && (
          <div className="two-col">
            <div className="subpanel">
              <h3>Live Scan Logs</h3>
              <div className="log-console">
                {scanLogs.length > 0 ? (
                  scanLogs.map((line, index) => (
                    <div key={`${index}-${line}`} className="log-line">
                      {line}
                    </div>
                  ))
                ) : (
                  <p className="muted-text">No scan log events yet.</p>
                )}
              </div>
            </div>

            <div className="subpanel">
              <h3>Role Export Preview</h3>
              <div className="button-row">
                <button type="button" onClick={() => previewReport()}>
                  Preview {selectedRoleExport.title}
                </button>
                <button type="button" onClick={openLastExport} disabled={!lastExport}>
                  Open Last Export
                </button>
              </div>
              <p className="muted-text">
                Preview opens in the dock at top of workspace so it is visible from all sections.
              </p>
            </div>
          </div>
        )}
      </section>
    );
  };

  const renderThreatModel = (): React.JSX.Element => {
    const report = threatModel?.report;
    const jsonText = report ? JSON.stringify(report, null, 2) : "";
    const framework = report?.framework || threatModelFramework;
    const frameworkLabel =
      framework === "OWASP" ? "OWASP" : framework === "PASTA" ? "PASTA" : framework === "DREAD" ? "DREAD" : "STRIDE";
    const diagramNodes = report
      ? [
          { title: "Application UI", detail: "Threat Modeling workspace" },
          { title: "Security bridge", detail: "IPC boundary and request validation" },
          { title: "Desktop service", detail: "Privileged application services" },
          { title: "Analysis engine", detail: frameworkLabel },
          { title: "Report exporter", detail: "JSON, HTML, Mermaid artifacts" },
          { title: "Local scan store", detail: "Saved reports and analysis history" },
        ]
      : [];
    const jumpToThreat = (anchor: string): void => {
      document.getElementById(anchor)?.scrollIntoView({ behavior: "smooth", block: "start" });
    };
    const categoryCounts = report
      ? report.threats.reduce(
          (acc, threat) => {
            const key = threat.framework_category || threat.stride_category;
            acc[key] = (acc[key] || 0) + 1;
            return acc;
          },
          {} as Record<string, number>,
        )
      : {};
    const categoryEntries = Object.entries(categoryCounts).sort((left, right) => right[1] - left[1]).slice(0, 8);
    const threatLinks = report
      ? report.threats.map((threat, index) => {
          const threatId = threat.threat_id || `TM-${index + 1}`;
          const anchor = `threat-${threatId}`;
          return (
            <button key={anchor} type="button" className="threat-model-link" onClick={() => jumpToThreat(anchor)}>
              {threatId}: {threat.title}
            </button>
          );
      })
      : [];
    const hasOverviewComponents = Boolean(report && report.system_overview.main_components.length > 0);
    const hasExternalIntegrations = Boolean(report && report.system_overview.external_integrations.length > 0);
    const hasAssets = Boolean(report && report.assets.length > 0);
    const hasSecurityObjectives = Boolean(report && report.security_objectives.length > 0);
    const hasAttackSurface = Boolean(report && report.entry_points.length > 0);
    const hasTrustBoundaries = Boolean(report && report.trust_boundaries.length > 0);
    const hasDataFlows = Boolean(report && report.data_flows.length > 0);
    const hasThreats = Boolean(report && report.threats.length > 0);
    const hasCodeMappings = Boolean(report && report.code_mappings.length > 0);
    const hasValidationPlan = Boolean(report && report.validation_plan.length > 0);
    const hasTraceability = Boolean(report && report.traceability.length > 0);
    const hasResidualRisk = Boolean(report && report.residual_risk.length > 0);
    const hasAssumptions = Boolean(report && report.assumptions.length > 0);
    const hasDreadDetails = Boolean(report && report.threats.some((threat) => Boolean(threat.dread_breakdown)));

    return (
      <section className="panel stack-gap">
        <div className="subpanel stack-gap">
          <h3>Threat Modeling</h3>
          <p className="muted-text">
            This workflow is independent from the canonical scan. It reads source code only, infers architecture from the selected codebase, and generates a methodology-specific threat model.
          </p>
          <div className="header-row">
            <label htmlFor="threatModelPath">Target Source Path</label>
            <input
              id="threatModelPath"
              value={threatModelPath}
              onChange={(event) => setThreatModelPath(event.target.value)}
              placeholder="C:\\projects\\app-or-repo"
            />
            <label htmlFor="threatModelFramework">Methodology</label>
            <select
              id="threatModelFramework"
              value={threatModelFramework}
              onChange={(event) => setThreatModelFramework(event.target.value as ThreatModelFramework)}
            >
              <option value="STRIDE">STRIDE</option>
              <option value="DREAD">DREAD</option>
              <option value="OWASP">OWASP</option>
              <option value="PASTA">PASTA</option>
            </select>
            <button type="button" onClick={browseThreatModelProject}>
              Browse
            </button>
            <button type="button" onClick={createThreatModel} disabled={isThreatModeling}>
              {isThreatModeling ? "Generating Threat Model..." : "Generate Threat Model"}
            </button>
            <button type="button" onClick={() => void window.codeSentinelX.openPath(lastThreatModelHtml)} disabled={!lastThreatModelHtml}>
              Open HTML
            </button>
            <button type="button" onClick={() => void window.codeSentinelX.openPath(lastThreatModelJson)} disabled={!lastThreatModelJson}>
              Open JSON
            </button>
            <button type="button" onClick={() => void window.codeSentinelX.openPath(lastThreatModelMermaid)} disabled={!lastThreatModelMermaid}>
              Open Mermaid
            </button>
          </div>
          <p className="role-hint">{threatModelStatus}</p>
          <p className="role-hint">Selected methodology: {frameworkLabel}</p>
          <p className="role-hint">Threat model target selection does not affect canonical scan history or report exports.</p>
        </div>

        {!report ? (
          <EmptyState text="Browse a project file or folder, then create a threat model to see the selected framework output." />
        ) : (
          <>
            <div className="subpanel">
              <h3>Executive Overview</h3>
              <div className="metric-grid">
                <div className="metric-card">
                  <p>Application Type</p>
                  <h4>{report.system_overview.application_type}</h4>
                </div>
                <div className="metric-card">
                  <p>Source Files</p>
                  <h4>{report.summary.source_files_analyzed}</h4>
                </div>
                <div className="metric-card">
                  <p>Assets</p>
                  <h4>{report.summary.assets}</h4>
                </div>
                <div className="metric-card">
                  <p>Entry Points</p>
                  <h4>{report.summary.entry_points}</h4>
                </div>
                <div className="metric-card">
                  <p>Threats</p>
                  <h4>{report.summary.threats}</h4>
                </div>
              </div>
              <div className="metric-card" style={{ marginTop: "12px" }}>
                <p>Methodology</p>
                <h4>{frameworkLabel}</h4>
              </div>
              {(hasOverviewComponents || hasExternalIntegrations) && (
                <div className="table-split-grid">
                  {hasOverviewComponents && (
                    <div>
                      <h4>Primary Components</h4>
                      <ul className="landing-story-list">
                        {report.system_overview.main_components.map((item) => <li key={item}>{item}</li>)}
                      </ul>
                    </div>
                  )}
                  {hasExternalIntegrations && (
                    <div>
                      <h4>External Integrations</h4>
                      <ul className="landing-story-list">
                        {report.system_overview.external_integrations.map((item) => <li key={item}>{item}</li>)}
                      </ul>
                    </div>
                  )}
                </div>
              )}
            </div>

            {hasAssets && (
              <div className="subpanel">
                <h3>Asset Inventory</h3>
                <table className="simple-table">
                  <thead>
                    <tr>
                      <th>ID</th>
                      <th>Name</th>
                      <th>Category</th>
                      <th>Sensitivity</th>
                      <th>Location</th>
                      <th>Evidence</th>
                      <th>Description</th>
                    </tr>
                  </thead>
                  <tbody>
                    {report.assets.map((asset) => (
                      <tr key={asset.asset_id}>
                        <td>{asset.asset_id}</td>
                        <td>{asset.name}</td>
                        <td>{asset.category}</td>
                        <td>{asset.sensitivity}</td>
                        <td>{asset.location}</td>
                        <td>
                          <ul className="landing-story-list">
                            {(asset.evidence || []).map((hit) => (
                              <li key={`${asset.asset_id}-${hit.file}:${hit.line}`}>
                                {hit.file}:{hit.line} - {hit.excerpt}
                              </li>
                            ))}
                          </ul>
                        </td>
                        <td>{asset.description}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            {hasSecurityObjectives && (
              <div className="subpanel">
                <h3>Assets and Security Objectives</h3>
                <table className="simple-table">
                  <thead>
                    <tr>
                      <th>Asset</th>
                      <th>Confidentiality</th>
                      <th>Integrity</th>
                      <th>Availability</th>
                      <th>Rationale</th>
                    </tr>
                  </thead>
                  <tbody>
                    {report.security_objectives.map((item) => (
                      <tr key={item.asset_id}>
                        <td>{item.asset_id}</td>
                        <td>{item.confidentiality}</td>
                        <td>{item.integrity}</td>
                        <td>{item.availability}</td>
                        <td>{item.rationale}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            {hasAttackSurface && (
              <div className="subpanel">
                <h3>Attack Surface</h3>
                <table className="simple-table">
                  <thead>
                    <tr>
                      <th>Name</th>
                      <th>Type</th>
                      <th>Exposure</th>
                      <th>Location</th>
                      <th>Details</th>
                    </tr>
                  </thead>
                  <tbody>
                    {report.entry_points.map((entry) => (
                      <tr key={`${entry.file}:${entry.line}:${entry.name}`}>
                        <td>{entry.name}</td>
                        <td>{entry.type}</td>
                        <td>{entry.exposure}</td>
                        <td>
                          <button type="button" onClick={() => void window.codeSentinelX.openPath(entry.file)}>
                            {entry.file}:{entry.line}
                          </button>
                        </td>
                        <td>{entry.details}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            {hasTrustBoundaries && (
              <div className="subpanel">
                <h3>Trust Boundaries</h3>
                <table className="simple-table">
                  <thead>
                    <tr>
                      <th>From</th>
                      <th>To</th>
                      <th>Data</th>
                      <th>Description</th>
                    </tr>
                  </thead>
                  <tbody>
                    {report.trust_boundaries.map((boundary, index) => (
                      <tr key={`${boundary.from}-${boundary.to}-${index}`}>
                        <td>{boundary.from}</td>
                        <td>{boundary.to}</td>
                        <td>{boundary.data.join(", ")}</td>
                        <td>{boundary.description}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            {hasDataFlows && (
              <div className="subpanel">
                <h3>Data Flows</h3>
                <table className="simple-table">
                  <thead>
                    <tr>
                      <th>Source</th>
                      <th>Destination</th>
                      <th>Data</th>
                      <th>Description</th>
                    </tr>
                  </thead>
                  <tbody>
                    {report.data_flows.map((flow, index) => (
                      <tr key={`${flow.source}-${flow.destination}-${index}`}>
                        <td>{flow.source}</td>
                        <td>{flow.destination}</td>
                        <td>{flow.data}</td>
                        <td>{flow.description}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            {hasThreats && (
              <div className="subpanel">
                <h3>Threat Register ({frameworkLabel})</h3>
                <div className="metric-grid">
                  <MetricCard label="Total Threats" value={String(report.threats.length)} />
                  {framework === "STRIDE" ? (
                    <>
                      <MetricCard label="Spoofing" value={String(categoryCounts.Spoofing || 0)} />
                      <MetricCard label="Tampering" value={String(categoryCounts.Tampering || 0)} />
                      <MetricCard label="Repudiation" value={String(categoryCounts.Repudiation || 0)} />
                      <MetricCard label="Information Disclosure" value={String(categoryCounts["Information Disclosure"] || 0)} />
                      <MetricCard label="Denial of Service" value={String(categoryCounts["Denial of Service"] || 0)} />
                      <MetricCard label="Elevation of Privilege" value={String(categoryCounts["Elevation of Privilege"] || 0)} />
                    </>
                  ) : (
                    <>
                      <MetricCard label="Methodology Categories" value={String(categoryEntries.length)} />
                      <MetricCard label="Validated Threats" value={String(report.threats.filter((item) => item.review_status === "Validated by reviewer").length)} />
                      <MetricCard label="Needs Review" value={String(report.threats.filter((item) => item.review_status !== "Validated by reviewer").length)} />
                      {hasDreadDetails && <MetricCard label="DREAD Profiles" value={String(report.threats.filter((item) => Boolean(item.dread_breakdown)).length)} />}
                    </>
                  )}
                </div>
                <div className="threat-model-link-bar">
                  {threatLinks}
                </div>
                {framework !== "STRIDE" && categoryEntries.length > 0 && (
                  <div className="subpanel" style={{ marginTop: "12px" }}>
                    <h4>Methodology Category Breakdown</h4>
                    <table className="simple-table">
                      <thead>
                        <tr>
                          <th>Category</th>
                          <th>Count</th>
                        </tr>
                      </thead>
                      <tbody>
                        {categoryEntries.map(([category, count]) => (
                          <tr key={category}>
                            <td>{category}</td>
                            <td>{count}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
                <div className="threat-model-card-grid">
                  {report.threats.map((threat, index) => {
                    const threatId = threat.threat_id || `TM-${index + 1}`;
                    const evidence = threat.evidence || [];
                    return (
                      <details key={`${threatId}-${threat.title}`} className="subpanel threat-model-card" id={`threat-${threatId}`}>
                        <summary className="threat-model-card-header">
                          <div>
                            <p className="eyebrow">Threat {threatId}</p>
                            <h4>{threat.title}</h4>
                          </div>
                          <span className="stride-pill">{threat.framework_category || threat.stride_category}</span>
                        </summary>
                        <div className="threat-model-card-body">
                          <p><strong>Component:</strong> {threat.component}</p>
                          <p><strong>Methodology:</strong> {frameworkLabel}</p>
                          <p><strong>Classification:</strong> {threat.framework_category || threat.stride_category}</p>
                          <p><strong>Impact:</strong> {threat.impact} | <strong>Likelihood:</strong> {threat.likelihood} | <strong>Exposure:</strong> {threat.exposure}</p>
                          <p><strong>Risk Score:</strong> {threat.risk_score ?? "N/A"} ({threat.risk_level || "N/A"})</p>
                          <p><strong>Review Status:</strong> {threat.review_status || "Pending review"}</p>
                          <p><strong>Description:</strong> {threat.description}</p>
                          {threat.owasp_category && (
                            <p><strong>OWASP Category:</strong> {threat.owasp_category}</p>
                          )}
                          {threat.pasta_stage && (
                            <p><strong>PASTA Stage:</strong> {threat.pasta_stage}</p>
                          )}
                          {threat.dread_breakdown && (
                            <table className="simple-table">
                              <thead>
                                <tr>
                                  <th>Damage</th>
                                  <th>Reproducibility</th>
                                  <th>Exploitability</th>
                                  <th>Affected Users</th>
                                  <th>Discoverability</th>
                                </tr>
                              </thead>
                              <tbody>
                                <tr>
                                  <td>{threat.dread_breakdown.damage}</td>
                                  <td>{threat.dread_breakdown.reproducibility}</td>
                                  <td>{threat.dread_breakdown.exploitability}</td>
                                  <td>{threat.dread_breakdown.affected_users}</td>
                                  <td>{threat.dread_breakdown.discoverability}</td>
                                </tr>
                              </tbody>
                            </table>
                          )}
                          <p><strong>Evidence:</strong></p>
                          {evidence.length > 0 ? (
                            <ul className="landing-story-list">
                              {evidence.map((hit) => (
                                <li key={`${hit.file}:${hit.line}`}>
                                  {hit.file}:{hit.line} - {hit.excerpt}
                                </li>
                              ))}
                            </ul>
                          ) : (
                            <p className="muted-text">Needs reviewer validation.</p>
                          )}
                          <p><strong>Root Cause:</strong> {threat.root_cause || "Derived from direct code evidence."}</p>
                          <p><strong>Abuse Case:</strong> {threat.abuse_case}</p>
                          <p><strong>Mitigation:</strong> {threat.mitigation}</p>
                        </div>
                      </details>
                    );
                  })}
                </div>
                <table className="simple-table">
                  <thead>
                    <tr>
                      <th title="Stable identifier assigned to the threat entry.">ID</th>
                      <th title="Short name describing the threat scenario.">Title</th>
                      <th title="Codebase component or subsystem affected by the threat.">Component</th>
                      <th title="Threat modeling category or framework classification.">Classification</th>
                      <th title="Business or technical impact if the threat is realized.">Impact</th>
                      <th title="Estimated likelihood that the threat can be exercised.">Likelihood</th>
                      <th title="Exposure context for the threat: public, authenticated, or internal.">Exposure</th>
                      <th title="Risk score and severity level derived from the threat model.">Risk</th>
                      <th title="Review status describing whether the threat has been validated by a reviewer.">Review Status</th>
                      <th title="Observed code root cause or direct evidence supporting the threat.">Root Cause</th>
                      <th title="Practical attack path describing how the threat can be abused.">Abuse Case</th>
                      <th title="Actionable guidance for reducing or eliminating the threat.">Mitigation</th>
                    </tr>
                  </thead>
                  <tbody>
                    {report.threats.map((threat, index) => (
                      <tr key={`${threat.title}-${index}`}>
                        <td>{threat.threat_id || `TM-${index + 1}`}</td>
                        <td>{threat.title}</td>
                        <td>{threat.component}</td>
                        <td>{threat.framework_category || threat.stride_category}</td>
                        <td>{threat.impact}</td>
                        <td>{threat.likelihood}</td>
                        <td>{threat.exposure}</td>
                        <td>{threat.risk_score ?? "N/A"} ({threat.risk_level || "N/A"})</td>
                        <td>{threat.review_status || "Pending reviewer validation"}</td>
                        <td>{threat.root_cause || "Derived from direct code evidence."}</td>
                        <td>{threat.abuse_case}</td>
                        <td>{threat.mitigation}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            {hasCodeMappings && (
              <div className="subpanel">
                <h3>Vulnerabilities Mapped to Code</h3>
                <table className="simple-table">
                  <thead>
                    <tr>
                      <th>Threat</th>
                      <th>Component</th>
                      <th>File</th>
                      <th>Line</th>
                      <th>Root Cause</th>
                      <th>CWE</th>
                    </tr>
                  </thead>
                  <tbody>
                    {report.code_mappings.map((item) => (
                      <tr key={`${item.threat_id}-${item.file}:${item.line}`}>
                        <td>{item.threat_id}</td>
                        <td>{item.component}</td>
                        <td>{item.file}</td>
                        <td>{item.line}</td>
                        <td>{item.root_cause}</td>
                        <td>{item.cwe || ""}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            {hasValidationPlan && (
              <div className="subpanel">
                <h3>Validation & Test Strategy</h3>
                <table className="simple-table">
                  <thead>
                    <tr>
                      <th>Threat</th>
                      <th>Check</th>
                      <th>Expected Verification</th>
                    </tr>
                  </thead>
                  <tbody>
                    {report.validation_plan.map((item) => (
                      <tr key={item.threat_id}>
                        <td>{item.threat_id}</td>
                        <td>{item.check}</td>
                        <td>{item.expected_verification}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            {hasTraceability && (
              <div className="subpanel">
                <h3>Traceability</h3>
                <table className="simple-table">
                  <thead>
                    <tr>
                      <th>Threat</th>
                      <th>Evidence</th>
                      <th>Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {report.traceability.map((item) => (
                      <tr key={item.threat_id}>
                        <td>{item.threat_id}</td>
                        <td>{item.evidence}</td>
                        <td>{item.status}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            {(hasResidualRisk || hasAssumptions) && (
              <div className="subpanel">
                <h3>Residual Risk & Assumptions</h3>
                {hasResidualRisk && (
                  <>
                    <h4>Residual Risk</h4>
                    <ul className="landing-story-list">
                      {report.residual_risk.map((item) => <li key={item}>{item}</li>)}
                    </ul>
                  </>
                )}
                {hasAssumptions && (
                  <>
                    <h4>Assumptions</h4>
                    <ul className="landing-story-list">
                      {report.assumptions.map((item) => <li key={item}>{item}</li>)}
                    </ul>
                  </>
                )}
              </div>
            )}

            <div className="subpanel">
              <h3>Architecture Diagram</h3>
              <div
                style={{
                  display: "flex",
                  flexDirection: "column",
                  gap: "12px",
                  border: "1px solid rgba(120,168,205,.18)",
                  borderRadius: "16px",
                  padding: "16px",
                  background: "rgba(255,255,255,.02)",
                }}
              >
                <div
                  style={{
                    alignSelf: "flex-start",
                    padding: "6px 10px",
                    borderRadius: "999px",
                    border: "1px solid rgba(120,168,205,.22)",
                    background: "rgba(255,255,255,.03)",
                    color: "#b8cadc",
                    fontSize: ".82rem",
                  }}
                >
                  Application boundary
                </div>
                <div
                  style={{
                    display: "grid",
                    gridTemplateColumns: "repeat(11, minmax(0, 1fr))",
                    gap: "10px",
                    alignItems: "stretch",
                  }}
                >
                  {diagramNodes.map((node, index) => (
                    <React.Fragment key={node.title}>
                      <div
                        style={{
                          gridColumn: "span 2",
                          minHeight: "92px",
                          border: "1px solid rgba(120,168,205,.22)",
                          borderRadius: "14px",
                          padding: "12px",
                          background: "linear-gradient(180deg, rgba(255,255,255,.05), rgba(255,255,255,.02))",
                          display: "flex",
                          flexDirection: "column",
                          justifyContent: "center",
                          textAlign: "center",
                        }}
                      >
                        <div style={{ fontWeight: 700, marginBottom: "6px" }}>{node.title}</div>
                        <div style={{ color: "#9ab0c8", fontSize: ".9rem", lineHeight: 1.35 }}>{node.detail}</div>
                      </div>
                      {index < diagramNodes.length - 1 && (
                        <div
                          style={{
                            gridColumn: "span 1",
                            display: "flex",
                            alignItems: "center",
                            justifyContent: "center",
                            color: "#7ecbff",
                            fontSize: "1.4rem",
                            fontWeight: 700,
                          }}
                        >
                          →
                        </div>
                      )}
                    </React.Fragment>
                  ))}
                </div>
                <div
                  style={{
                    alignSelf: "flex-start",
                    padding: "6px 10px",
                    borderRadius: "999px",
                    border: "1px solid rgba(120,168,205,.22)",
                    background: "rgba(255,255,255,.03)",
                    color: "#b8cadc",
                    fontSize: ".82rem",
                  }}
                >
                  Privileged desktop boundary
                </div>
                <details>
                  <summary className="role-hint" style={{ cursor: "pointer" }}>
                    View diagram source
                  </summary>
                  <pre>{report.diagram}</pre>
                </details>
              </div>
            </div>

            <div className="subpanel">
              <h3>JSON Output</h3>
              <pre>{jsonText}</pre>
            </div>
          </>
        )}
      </section>
    );
  };

  const renderExistingReport = (): React.JSX.Element => {
    if (!scan) {
      return <EmptyState text="Run a scan to generate Existing Security Implementation report." />;
    }
    const report = scan.report.existing_implementation_report;
    return (
      <section className="panel stack-gap">
        <h2>{report.title}</h2>
        <p>Target: {report.target_path}</p>
        <p>Generated: {report.generated_at}</p>

        <SubTabs
          tabs={[
            { key: "summary", label: "Summary", icon: "SM" },
            { key: "controls", label: "Controls", icon: "CT" },
            { key: "compliance", label: "Compliance", icon: "CP" },
          ]}
          active={existingSection}
          onChange={(value) => setExistingSection(value as ExistingSection)}
        />

        {existingSection === "summary" && (
          <div className="metric-grid">
            <MetricCard label="Implemented Controls" value={String(report.summary.implemented_controls)} />
            <MetricCard label="Security Categories" value={String(Object.keys(report.summary.category_distribution || {}).length)} />
            <MetricCard label="Standards Mapped" value={String(Object.keys(report.summary.standards_coverage || {}).length)} />
            <MetricCard
              label="Enterprise Status"
              value={(enterpriseAssurance?.status || "blocked").toUpperCase()}
            />
            <MetricCard label="Readiness Score" value={String(enterpriseAssurance?.readiness_score ?? 0)} />
            <MetricCard
              label="Required Tool Coverage"
              value={formatPercent(enterpriseAssurance?.required_tools_coverage_percent)}
            />
          </div>
        )}

        {existingSection === "controls" && (
          <div className="subpanel">
            <h3>Implemented Controls</h3>
            <table className="simple-table">
              <thead>
                <tr>
                  <th>Control</th>
                  <th>Category</th>
                  <th>Coverage</th>
                  <th>Standards</th>
                </tr>
              </thead>
              <tbody>
                {report.controls.map((control) => (
                  <tr key={control.control_id}>
                    <td>{control.name}</td>
                    <td>{control.category}</td>
                    <td>{control.coverage_level}</td>
                    <td>{control.standard_mappings.join(", ")}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {existingSection === "compliance" && (
          <div className="subpanel">
            <h3>Compliance Matrix</h3>
            <table className="simple-table">
              <thead>
                <tr>
                  <th>Standard</th>
                  <th>Controls</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {report.compliance_matrix.map((item) => (
                  <tr key={`${item.standard}-${item.status}`}>
                    <td>{item.standard}</td>
                    <td>{item.control_count}</td>
                    <td>{item.status}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    );
  };

  const renderVulnerabilityReport = (): React.JSX.Element => {
    if (!scan) {
      return <EmptyState text="Run a scan to generate Vulnerability report." />;
    }

    return (
      <section className="panel stack-gap">
        <SubTabs
          tabs={[
            { key: "queue", label: "Findings Queue", icon: "Q" },
            { key: "detail", label: "Issue Detail", icon: "D" },
          ]}
          active={vulnerabilitySection}
          onChange={(value) => setVulnerabilitySection(value as VulnerabilitySection)}
        />

        {vulnerabilitySection === "queue" && (
          <>
            <div className="finding-toolbar">
              <div className="severity-group">
                <button className={severityFilter === "All" ? "active" : ""} onClick={() => setSeverityFilter("All")} type="button">
                  All
                </button>
                {SEVERITY_ORDER.map((severity) => (
                  <button
                    key={severity}
                    className={severityFilter === severity ? "active" : ""}
                    onClick={() => setSeverityFilter(severity)}
                    type="button"
                  >
                    {severity}
                  </button>
                ))}
              </div>
              <select value={findingScope} onChange={(event) => setFindingScope(event.target.value as FindingScope)}>
                <option value="all">All findings</option>
                <option value="new">New since last scan</option>
                <option value="changed">Changed files only</option>
              </select>
              <select value={findingGroupMode} onChange={(event) => setFindingGroupMode(event.target.value as FindingGroupMode)}>
                <option value="none">No grouping</option>
                <option value="module">Group by module</option>
                <option value="owner">Group by owner</option>
              </select>
              <input
                value={searchText}
                onChange={(event) => setSearchText(event.target.value)}
                placeholder="Search issue, CWE, OWASP, file"
              />
            </div>

            <div className="finding-queue">
              <table className="simple-table">
                <thead>
                  <tr>
                    <th>Severity</th>
                    <th>Issue</th>
                    <th>File</th>
                    <th>Owner</th>
                    <th>CVSS</th>
                    <th>Line</th>
                    <th>Status</th>
                  </tr>
                </thead>
                <tbody>
                  {groupedFilteredFindings.map((group) => (
                    <React.Fragment key={group.key}>
                      {findingGroupMode !== "none" && (
                        <tr className="group-row">
                          <td colSpan={7}>
                            {findingGroupMode === "module" ? "Module" : "Owner"}: {group.key} ({group.items.length})
                          </td>
                        </tr>
                      )}
                      {group.items.map((item) => (
                        <tr
                          key={item.finding_uid}
                          className={selectedFinding?.finding_uid === item.finding_uid ? "selected-row" : ""}
                          onClick={() => {
                            setSelectedFindingId(item.finding_uid);
                            setVulnerabilitySection("detail");
                          }}
                        >
                          <td>
                            <span className={`sev-pill sev-${item.severity}`}>{item.severity}</span>
                          </td>
                          <td>{item.vulnerability_title || item.vulnerability_type || "Issue"}</td>
                          <td>{normalizeFindingPath(item.file_path)}</td>
                          <td>{item.code_owner || "Unassigned"}</td>
                          <td>{(item.cvss_score || 0).toFixed(1)}</td>
                          <td>{item.line_number}</td>
                          <td>{item.status || "Open"}</td>
                        </tr>
                      ))}
                    </React.Fragment>
                  ))}
                  {filteredFindings.length === 0 && (
                    <tr>
                      <td colSpan={7}>No issues match this filter.</td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
            <p className="muted-text">Click a row to open the detailed finding tab.</p>
          </>
        )}

        {vulnerabilitySection === "detail" && (
          <div className="finding-detail">
            {selectedFinding ? (
              <>
                <h3>{selectedFinding.vulnerability_title || selectedFinding.vulnerability_type || "Issue"}</h3>
                <p>
                  {selectedFinding.severity} | CVSS {(selectedFinding.cvss_score || 0).toFixed(1)} | {selectedFinding.cwe_id} |{" "}
                  {selectedFinding.owasp_mapping}
                </p>
                <p>
                  <strong>Location:</strong> {normalizeFindingPath(selectedFinding.file_path)}:{selectedFinding.line_number}
                </p>
                <p>
                  <strong>Folder:</strong> {folderFromFindingPath(selectedFinding.file_path)}
                </p>
                <p>
                  <strong>Code Owner:</strong> {selectedFinding.code_owner || "Unassigned"}
                </p>
                <p>
                  <strong>Description:</strong> {selectedFinding.description || "No additional description available."}
                </p>
                <p>
                  <strong>Source Tool:</strong> {selectedFinding.tool || "CodeSentinelX"}
                </p>
                <p>
                  <strong>Rule Confidence:</strong>{" "}
                  {typeof selectedFinding.rule_confidence === "number"
                    ? `${selectedFinding.rule_confidence_label || "Medium"} (${selectedFinding.rule_confidence.toFixed(2)})`
                    : "Not scored"}
                </p>
                <p>
                  <strong>Remediation Confidence:</strong> {selectedFinding.remediation_confidence || "Not scored"}
                </p>
                {selectedFinding.dependency_reachability && selectedFinding.dependency_reachability.status !== "not_applicable" && (
                  <p>
                    <strong>Dependency Reachability:</strong> {selectedFinding.dependency_reachability.status} (
                    {selectedFinding.dependency_reachability.score.toFixed(2)}) -{" "}
                    {selectedFinding.dependency_reachability.reasoning || "No reasoning available."}
                  </p>
                )}
                <p>
                  <strong>Business Impact:</strong> {selectedFinding.business_impact}
                </p>
                <p>
                  <strong>Remediation:</strong> {selectedFinding.recommendation}
                </p>
                <h4>Code Evidence Excerpt</h4>
                <pre>{selectedFinding.code_evidence_excerpt || selectedFinding.source_line_snippet || "No source context captured."}</pre>
                <div className="code-grid">
                  <div>
                    <h4>Original Code</h4>
                    <pre>{selectedFinding.original_code || "Snippet unavailable."}</pre>
                  </div>
                  <div>
                    <h4>Suggested Fix</h4>
                    <pre>{selectedFinding.fixed_code || "No direct fix available."}</pre>
                  </div>
                </div>
                <h4>Exact Code Diff Fix</h4>
                <pre>{selectedFinding.patch_preview || "No patch preview available."}</pre>
                <div className="button-row">
                  <button
                    type="button"
                    onClick={() => copyFixCode(selectedFinding.fixed_code || "")}
                    disabled={!roleCaps.canCopyFixes}
                    title={!roleCaps.canCopyFixes ? `Role ${role} cannot copy fix snippets.` : ""}
                  >
                    Copy Fix
                  </button>
                  <button
                    type="button"
                    onClick={() => copyPatch(selectedFinding.finding_uid)}
                    disabled={!roleCaps.canCopyFixes}
                    title={!roleCaps.canCopyFixes ? `Role ${role} cannot copy remediation patches.` : ""}
                  >
                    Copy Patch
                  </button>
                  <button
                    type="button"
                    onClick={() => markReviewed(selectedFinding.finding_uid)}
                    disabled={!roleCaps.canReviewFindings}
                    title={!roleCaps.canReviewFindings ? `Role ${role} cannot mark issues.` : ""}
                  >
                    Mark Reviewed
                  </button>
                </div>
              </>
            ) : (
              <EmptyState text="Open a finding from the queue tab to view details." />
            )}
          </div>
        )}
      </section>
    );
  };

  const renderCompliance = (): React.JSX.Element => {
    if (!scan) {
      return <EmptyState text="Run a scan to view compliance mapping." />;
    }

    const compliance = profileCompliance;

    return (
      <section className="panel stack-gap">
        <SubTabs
          tabs={[
            { key: "profile", label: "Profile Coverage", icon: "PF" },
            { key: "matrix", label: "Compliance Matrix", icon: "MX" },
            { key: "actions", label: "Action Plan", icon: "AP" },
          ]}
          active={complianceSection}
          onChange={(value) => setComplianceSection(value as ComplianceSection)}
        />

        {complianceSection === "profile" && (
          <div className="subpanel stack-gap">
            {compliance ? (
              <>
                <div className="compliance-profile-header">
                  <div className="metric-card">
                    <p>Detected Scan Profile</p>
                    <h4>{compliance.scan_profile_label}</h4>
                  </div>
                  <div className="metric-card">
                    <p>Mapped Findings</p>
                    <h4>{compliance.summary.mapped_findings_total}</h4>
                  </div>
                  <div className="metric-card">
                    <p>Mapped Controls</p>
                    <h4>{compliance.summary.mapped_controls_total}</h4>
                  </div>
                  <div className="metric-card">
                    <p>Coverage Gaps</p>
                    <h4>{compliance.summary.items_gap}</h4>
                  </div>
                </div>

                <div className="compliance-version-row">
                  <span>OWASP Top 10: {compliance.framework_versions.owasp_top_10}</span>
                  <span>OWASP API Top 10: {compliance.framework_versions.owasp_api_top_10}</span>
                  <span>ASVS: {compliance.framework_versions.asvs}</span>
                  <span>WSTG: {compliance.framework_versions.wstg}</span>
                </div>

                {(compliance.frameworks || []).map((framework) => (
                  <div key={framework.framework_id} className="compliance-framework">
                    <div className="tool-manager-head">
                      <h3>{framework.label}</h3>
                      <span className={`profile-chip ${framework.applicable ? "profile-website" : "profile-ip"}`}>
                        {framework.applicable ? "Applicable" : "Not Applicable"}
                      </span>
                    </div>
                    <div className="tool-summary-grid">
                      <span>Covered: {framework.summary.covered}</span>
                      <span>Gap: {framework.summary.gap}</span>
                      <span>Not Applicable: {framework.summary.not_applicable}</span>
                      <span>Mapped Findings: {framework.summary.mapped_findings}</span>
                    </div>
                    <table className="simple-table">
                      <thead>
                        <tr>
                          <th>ID</th>
                          <th>Category</th>
                          <th>Status</th>
                          <th>Findings</th>
                          <th>Controls</th>
                          <th>Total</th>
                        </tr>
                      </thead>
                      <tbody>
                        {(framework.rows || []).map((row, index) => {
                          const rowAny = row as unknown as Record<string, unknown>;
                          const rowId = String(rowAny.id ?? rowAny.item_id ?? `ITEM-${index + 1}`);
                          const rowTitle = String(rowAny.title ?? rowAny.category ?? rowAny.name ?? "Unlabeled");
                          const statusRaw = String(rowAny.status ?? "gap");
                          const findings = Number(rowAny.finding_count ?? rowAny.findings ?? 0);
                          const controls = Number(rowAny.control_count ?? rowAny.controls ?? 0);
                          const total = Number(rowAny.count ?? (findings + controls));
                          return (
                          <tr key={`${framework.framework_id}-${rowId}-${index}`}>
                            <td>{rowId}</td>
                            <td>{rowTitle}</td>
                            <td>
                              <span className={`compliance-status compliance-${statusRaw}`}>
                                {statusRaw.replaceAll("_", " ")}
                              </span>
                            </td>
                            <td>{Number.isFinite(findings) ? findings : 0}</td>
                            <td>{Number.isFinite(controls) ? controls : 0}</td>
                            <td>{Number.isFinite(total) ? total : 0}</td>
                          </tr>
                        )})}
                      </tbody>
                    </table>
                  </div>
                ))}
              </>
            ) : (
              <EmptyState text="Profile-based coverage data is unavailable for this scan record." />
            )}
          </div>
        )}

        {complianceSection === "matrix" && (
          <div className="subpanel">
            <h3>Compliance Matrix</h3>
            <table className="simple-table">
              <thead>
                <tr>
                  <th>Standard</th>
                  <th>Controls</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {scan.report.existing_implementation_report.compliance_matrix.map((item) => (
                  <tr key={`${item.standard}-${item.status}`}>
                    <td>{item.standard}</td>
                    <td>{item.control_count}</td>
                    <td>{item.status}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {complianceSection === "actions" && (
          <div className="subpanel">
            <h3>Recommended Action Plan</h3>
            <ol>
              {(scan.report.executive_summary.recommended_action_plan || []).map((item) => (
                <li key={item}>{item}</li>
              ))}
            </ol>
          </div>
        )}
      </section>
    );
  };

  const renderHistory = (): React.JSX.Element => {
    return (
      <section className="panel stack-gap">
        <SubTabs
          tabs={[
            { key: "scans", label: "Scan History", icon: "SH" },
            { key: "audits", label: "Audit Logs", icon: "AL" },
            { key: "reports", label: "Reports", icon: "RP" },
          ]}
          active={historySection}
          onChange={(value) => setHistorySection(value as HistorySection)}
        />

        {historySection === "scans" && (
          <>
            {portfolioSummary && (
              <div className="subpanel">
                <h3>Local Portfolio Summary</h3>
                <div className="tool-summary-grid">
                  <span>Scans: {portfolioSummary.scansTotal}</span>
                  <span>Repositories: {portfolioSummary.repositoriesTotal}</span>
                  <span>
                    Trend: {portfolioSummary.trendDirection}
                    {portfolioSummary.trendDirection !== "unavailable" ? ` (${portfolioSummary.trendDelta > 0 ? "+" : ""}${portfolioSummary.trendDelta})` : ""}
                  </span>
                  <span>Fix velocity: {portfolioSummary.fixVelocityPercent.toFixed(1)}%</span>
                  <span>Suppression drift: {portfolioSummary.suppressionDriftScore.toFixed(1)}</span>
                </div>
                <div className="table-split-grid">
                  <div>
                    <h4>Repeated Hot Modules</h4>
                    <table className="simple-table">
                      <thead>
                        <tr>
                          <th>Module</th>
                          <th>Count</th>
                        </tr>
                      </thead>
                      <tbody>
                        {(portfolioSummary.hotModules || []).map((item) => (
                          <tr key={item.module}>
                            <td>{item.module}</td>
                            <td>{item.count}</td>
                          </tr>
                        ))}
                        {(portfolioSummary.hotModules || []).length === 0 && (
                          <tr>
                            <td colSpan={2}>No repeated hot modules yet.</td>
                          </tr>
                        )}
                      </tbody>
                    </table>
                  </div>
                  <div>
                    <h4>Recurring CWE Families</h4>
                    <table className="simple-table">
                      <thead>
                        <tr>
                          <th>CWE</th>
                          <th>Count</th>
                        </tr>
                      </thead>
                      <tbody>
                        {(portfolioSummary.recurringCwe || []).map((item) => (
                          <tr key={item.cwe}>
                            <td>{item.cwe}</td>
                            <td>{item.count}</td>
                          </tr>
                        ))}
                        {(portfolioSummary.recurringCwe || []).length === 0 && (
                          <tr>
                            <td colSpan={2}>No recurring CWE data yet.</td>
                          </tr>
                        )}
                      </tbody>
                    </table>
                  </div>
                </div>
              </div>
            )}

            <div className="subpanel">
              <h3>Scan History</h3>
              <table className="simple-table">
                <thead>
                  <tr>
                    <th>Scan ID</th>
                    <th>Project</th>
                    <th>Risk</th>
                    <th>Findings</th>
                    <th>Reviewed</th>
                    <th>Suppressed</th>
                    <th>Top Module</th>
                    <th>Role Views</th>
                    <th>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {history.map((item) => (
                    <tr key={item.scanId}>
                      <td>{item.scanId.slice(0, 8)}</td>
                      <td>{item.projectPath}</td>
                      <td>{item.risk}{typeof item.riskScore === "number" ? ` (${item.riskScore.toFixed(1)})` : ""}</td>
                      <td>{item.totalFindings}</td>
                      <td>{item.reviewedFindings || 0}</td>
                      <td>{item.suppressedCount || 0}</td>
                      <td>{item.topModule || "-"}</td>
                      <td>
                        <div className="role-chip-row" title="One stored scan can be opened as any role projection without rescanning.">
                          {(item.roleViewsAvailable || ROLES).map((availableRole) => (
                            <button
                              key={`${item.scanId}-${availableRole}`}
                              type="button"
                              className={availableRole === role ? "role-chip active" : "role-chip"}
                              onClick={() => {
                                setRole(availableRole);
                                void openScan(item.scanId, availableRole);
                              }}
                            >
                              {availableRole}
                            </button>
                          ))}
                        </div>
                      </td>
                      <td>
                        <button type="button" onClick={() => openScan(item.scanId)}>
                          Open
                        </button>
                      </td>
                    </tr>
                  ))}
                  {history.length === 0 && (
                    <tr>
                      <td colSpan={9}>No scan history yet.</td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </>
        )}

        {historySection === "audits" && (
          <div className="subpanel">
            <h3>Audit Logs</h3>
            <table className="simple-table">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Action</th>
                  <th>Actor</th>
                  <th>Details</th>
                </tr>
              </thead>
              <tbody>
                {audits.map((item) => (
                  <tr key={item.id}>
                    <td>{new Date(item.createdAt).toLocaleString()}</td>
                    <td>{item.action}</td>
                    <td>{item.actor}</td>
                    <td>{item.details}</td>
                  </tr>
                ))}
                {audits.length === 0 && (
                  <tr>
                    <td colSpan={4}>No audit records available.</td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        )}

        {historySection === "reports" && (
          <div className="subpanel">
            <h3>Reports History</h3>
            <div className="button-row" style={{ marginBottom: 10 }}>
              <button type="button" onClick={selectAllReports} disabled={reportHistory.length === 0}>
                Select All
              </button>
              <button type="button" onClick={clearReportSelection} disabled={selectedReportPaths.size === 0}>
                Clear Selection
              </button>
              <button type="button" onClick={() => void deleteSelectedReports()} disabled={selectedReportPaths.size === 0}>
                Delete Selected
              </button>
              <button type="button" onClick={() => void deleteAllReports()} disabled={reportHistory.length === 0}>
                Delete All
              </button>
            </div>
            <table className="simple-table">
              <thead>
                <tr>
                  <th>Select</th>
                  <th>Time</th>
                  <th>Role Scope</th>
                  <th>Report</th>
                  <th>Target</th>
                  <th>Format</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {reportHistory.map((item) => (
                  <tr key={item.fullPath}>
                    <td>
                      <input
                        type="checkbox"
                        checked={selectedReportPaths.has(item.fullPath)}
                        onChange={() => toggleReportSelection(item.fullPath)}
                      />
                    </td>
                    <td>{item.generatedAt ? new Date(item.generatedAt).toLocaleString() : "-"}</td>
                    <td>{item.roleScope}</td>
                    <td>{item.reportType}</td>
                    <td>{item.target || "-"}</td>
                    <td>{item.format.toUpperCase()}</td>
                    <td>
                      <button type="button" onClick={() => void window.codeSentinelX.openPath(item.fullPath)}>
                        Open
                      </button>
                    </td>
                  </tr>
                ))}
                {reportHistory.length === 0 && (
                  <tr>
                    <td colSpan={7}>No exported reports yet.</td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        )}
      </section>
    );
  };

  const renderHelp = (): React.JSX.Element => {
    const renderHelpLines = (lines: string[]): React.JSX.Element[] => {
      const blocks: React.JSX.Element[] = [];
      let bulletBuffer: string[] = [];
      let numberBuffer: string[] = [];

      const flushBullets = (keyPrefix: string): void => {
        if (!bulletBuffer.length) {
          return;
        }
        blocks.push(
          <ul key={`${keyPrefix}-bullets`} className="landing-story-list" style={{ marginTop: 8 }}>
            {bulletBuffer.map((item, idx) => (
              <li key={`${keyPrefix}-b-${idx}`}>{item}</li>
            ))}
          </ul>,
        );
        bulletBuffer = [];
      };

      const flushNumbers = (keyPrefix: string): void => {
        if (!numberBuffer.length) {
          return;
        }
        blocks.push(
          <ol key={`${keyPrefix}-numbers`} style={{ marginTop: 8, paddingLeft: 20 }}>
            {numberBuffer.map((item, idx) => (
              <li key={`${keyPrefix}-n-${idx}`} style={{ marginBottom: 6 }}>{item}</li>
            ))}
          </ol>,
        );
        numberBuffer = [];
      };

      lines.forEach((raw, index) => {
        const line = String(raw || "");
        const key = `help-line-${index}`;
        const h3 = /^###\s+(.+)$/.exec(line);
        const bullet = /^-\s+(.+)$/.exec(line);
        const numbered = /^(\d+)\.\s+(.+)$/.exec(line);
        if (h3) {
          flushBullets(`${key}-before-h3`);
          flushNumbers(`${key}-before-h3`);
          blocks.push(<h4 key={key} style={{ marginTop: 14, marginBottom: 8 }}>{h3[1].trim()}</h4>);
          return;
        }
        if (bullet) {
          flushNumbers(`${key}-before-bullet`);
          bulletBuffer.push(bullet[1].trim());
          return;
        }
        if (numbered) {
          flushBullets(`${key}-before-numbered`);
          numberBuffer.push(numbered[2].trim());
          return;
        }
        if (!line.trim()) {
          flushBullets(`${key}-blank`);
          flushNumbers(`${key}-blank`);
          return;
        }
        flushBullets(`${key}-before-text`);
        flushNumbers(`${key}-before-text`);
        blocks.push(
          <p key={key} className="muted-text" style={{ marginBottom: 8 }}>
            {line}
          </p>,
        );
      });

      flushBullets("help-end");
      flushNumbers("help-end");
      return blocks;
    };

    return (
      <section className="panel stack-gap">
        <div className="subpanel">
          <h3>Help Center</h3>
          <p className="muted-text">
            End-to-end documentation is available in-app, markdown, and PDF. This guide is role-aware and explains scan/report behavior, troubleshooting, and technical term definitions.
          </p>
          <div className="button-row">
            <button type="button" onClick={() => void loadHelpGuide()}>
              Refresh Help Content
            </button>
            <button type="button" onClick={() => void openHelpHtml()}>
              Open Help HTML
            </button>
            <button type="button" onClick={() => void openHelpPdf()}>
              Open Help PDF
            </button>
            <button type="button" onClick={() => void openHelpMarkdownFile()} disabled={!helpGuideMarkdownPath}>
              Open README_USER_GUIDE.md
            </button>
          </div>
          <p className="muted-text">Markdown Path: {helpGuideMarkdownPath || "-"}</p>
          <p className="muted-text">HTML Path: {helpGuideHtmlPath || "-"}</p>
          <p className="muted-text">PDF Path: {helpGuidePdfPath || "-"}</p>
        </div>

        <div className="subpanel">
          <h3>Guide Content</h3>
          {helpGuideMarkdown.trim() ? (
            <>
              <div className="button-row" style={{ marginBottom: 12 }}>
                <input
                  type="search"
                  value={helpSearchText}
                  onChange={(event) => setHelpSearchText(event.target.value)}
                  placeholder="Search help sections and content..."
                  style={{ minWidth: 360 }}
                />
                <button type="button" onClick={() => setHelpSearchText("")} disabled={!helpSearchText.trim()}>
                  Clear Search
                </button>
                <span className="muted-text">
                  Sections: {filteredHelpSections.length}/{helpSections.length}
                </span>
              </div>
              <div className="help-hero-cards" style={{ display: "grid", gridTemplateColumns: "repeat(4, minmax(0, 1fr))", gap: 10, marginBottom: 14 }}>
                <div className="table-frame" style={{ padding: 12 }}>
                  <strong>Role-first guide</strong>
                  <p className="muted-text">Content is organized around real app roles, report types, and workflows.</p>
                </div>
                <div className="table-frame" style={{ padding: 12 }}>
                  <strong>Interactive nav</strong>
                  <p className="muted-text">Jump to sections with the sticky navigation on the left.</p>
                </div>
                <div className="table-frame" style={{ padding: 12 }}>
                  <strong>Website layout</strong>
                  <p className="muted-text">The HTML guide renders as a styled help page, not a flat document.</p>
                </div>
                <div className="table-frame" style={{ padding: 12 }}>
                  <strong>Searchable</strong>
                  <p className="muted-text">Search the guide by section title or any line of text.</p>
                </div>
              </div>
              <div style={{ display: "grid", gridTemplateColumns: "300px 1fr", gap: 14 }}>
                <div
                  className="table-frame"
                  style={{ padding: 10, position: "sticky", top: 8, alignSelf: "start", maxHeight: 680, overflowY: "auto" }}
                >
                  <h4 style={{ marginBottom: 10 }}>Section Navigation</h4>
                  {filteredHelpSections.length ? (
                    <ol style={{ margin: 0, paddingLeft: 18 }}>
                      {filteredHelpSections.map((section) => (
                        <li key={section.id} style={{ marginBottom: 8 }}>
                          <button
                            type="button"
                            className="fix-link"
                            onClick={() => scrollHelpToSection(section.id)}
                            style={{ background: "none", border: "none", padding: 0, textAlign: "left", cursor: "pointer" }}
                          >
                            {section.title}
                          </button>
                        </li>
                      ))}
                    </ol>
                  ) : (
                    <p className="muted-text">No section matches your search.</p>
                  )}
                </div>
                <div style={{ maxHeight: 680, overflowY: "auto", paddingRight: 6 }}>
                  {filteredHelpSections.map((section) => (
                    <article key={section.id} id={section.id} className="table-frame" style={{ padding: 14, marginBottom: 12 }}>
                      <h3 style={{ marginBottom: 8 }}>{section.title}</h3>
                      {renderHelpLines(section.lines)}
                    </article>
                  ))}
                </div>
              </div>
            </>
          ) : (
            <EmptyState text="Help guide is not loaded yet." />
          )}
        </div>
      </section>
    );
  };

  const renderToolManager = (): React.JSX.Element => {
    if (toolAuthEnabled && !toolSessionValid) {
      return renderOwnerAccessPanel();
    }

    const isProfileSection = toolSection === "codebase";
    const profile = (isProfileSection ? toolSection : activeToolProfile) as ToolScanProfile;
    const profileMeta = TOOL_PROFILE_META[profile];
    const profileStats = toolProfileStats[profile];

    return (
      <section className="panel stack-gap">
        <SubTabs
          tabs={[
            { key: "codebase", label: "Codebase Tools", icon: "CB" },
            { key: "roles", label: "Role Drill-Down", icon: "RL" },
            { key: "policy", label: "Execution Policy", icon: "PL" },
          ]}
          active={toolSection}
          onChange={(value) => setToolSection(value as ToolManagerSection)}
        />
        {toolAuthEnabled && (
          <div className="tool-auth-meta">
            <span>
              Owner session: active{" "}
              {toolAuthConfig?.sessionExpiresAt ? `(expires ${new Date(toolAuthConfig.sessionExpiresAt).toLocaleTimeString()})` : ""}
            </span>
            <button type="button" onClick={logoutToolManagerSession} disabled={toolAuthBusy}>
              End Owner Session
            </button>
          </div>
        )}

        {isProfileSection && (
          <>
            <div className="subpanel">
              <div className="tool-manager-head">
                <h3>{profileMeta.label}</h3>
                <div className="tool-actions">
                  <button type="button" onClick={() => loadTools()}>
                    Refresh
                  </button>
                </div>
              </div>
              <p className="muted-text">{profileMeta.helper}</p>
              <p className="muted-text">
                Desktop execution, downloads, and bundled external binaries are disabled by policy. This catalog maps
                secure coding coverage only.
              </p>
              <div className="tool-summary-grid">
                <span>Catalog entries: {profileStats.total}</span>
                <span>Integrated references: {profileStats.integrated}</span>
                <span>Desktop execution: disabled</span>
                <span>Scope: local codebase folders only</span>
              </div>
              <input
                value={toolSearchText}
                onChange={(event) => setToolSearchText(event.target.value)}
                placeholder={`Search ${profileMeta.label.toLowerCase()} by tool, category, coverage...`}
              />
            </div>

            <div className="subpanel">
              <div className="table-scroll">
                <table className="simple-table tool-manager-table">
                  <thead>
                    <tr>
                      <th>Tool</th>
                      <th>Coverage Profile</th>
                      <th>Category</th>
                      <th>Codebase Modes</th>
                      <th>Vulnerability Coverage</th>
                      <th>Catalog Status</th>
                      <th>Execution Policy</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredToolRows.map((row) => {
                      const status = row.status;
                      const profileText = row.scan_profiles.map((item) => TOOL_PROFILE_META[item].label).join(", ");
                      const codebaseModes = row.target_modes.filter((item) => item === "codebase" || item === "remote-codebase");
                      return (
                        <tr key={row.name}>
                          <td>
                            <span
                              className="tool-name-chip"
                              title={`${row.description}\n${row.homepage || ""}\nProfiles: ${profileText}\n${
                                status?.message || row.host_message || ""
                              }`}
                            >
                              {row.display_name}
                            </span>
                          </td>
                          <td>
                            <div className="profile-chip-row">
                              {row.scan_profiles.map((item) => (
                                <span key={`${row.name}-${item}`} className={`profile-chip profile-${item}`}>
                                  {TOOL_PROFILE_META[item].label}
                                </span>
                              ))}
                            </div>
                          </td>
                          <td>{row.category}</td>
                          <td>{codebaseModes.length > 0 ? codebaseModes.join(", ") : "codebase"}</td>
                          <td>{row.vulnerability_classes.join(", ")}</td>
                          <td>{row.integrated ? "Catalog reference" : status?.available ? "Available" : "Reference only"}</td>
                          <td>Install/run disabled in desktop by policy</td>
                        </tr>
                      );
                    })}
                    {filteredToolRows.length === 0 && (
                      <tr>
                        <td colSpan={7}>No tools match this profile/search.</td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          </>
        )}

        {toolSection === "roles" && (
          <div className="subpanel">
            <h3>Role Drill-Down Purpose</h3>
            <p className="muted-text">
              Role drill-down sets who sees which depth first, so each team focuses on the right remediation workflow.
            </p>
            <table className="simple-table">
              <thead>
                <tr>
                  <th>Role</th>
                  <th>Primary Purpose</th>
                  <th>Drill-Down Use</th>
                  <th>Primary Actions</th>
                </tr>
              </thead>
              <tbody>
                {ROLE_DRILLDOWN.map((item) => (
                  <tr key={item.role} className={item.role === role ? "selected-row" : ""}>
                    <td>{item.role}</td>
                    <td>{item.purpose}</td>
                    <td>{item.drillDownUse}</td>
                    <td>{item.primaryActions}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {toolSection === "policy" && (
          <>
            <div className="subpanel">
              <div className="tool-manager-head">
                <h3>Desktop Execution Policy</h3>
                <div className="tool-actions">
                  <button
                    type="button"
                    className="danger-button"
                    onClick={resetLocalStateCache}
                    disabled={toolBusyKey === "reset-local-state-cache" || !roleCaps.canProvisionTools || isScanning}
                    title={
                      !roleCaps.canProvisionTools
                        ? `Role ${role} cannot reset local state/cache.`
                        : isScanning
                          ? "Stop active scan before resetting local state/cache."
                          : "Clears local app state, local tool cache, and run cache."
                    }
                  >
                    {toolBusyKey === "reset-local-state-cache" ? "Resetting..." : "Reset Local State/Cache"}
                  </button>
                </div>
              </div>
              <p className="muted-text">
                CodeSentinelX desktop is locked to native secure code analysis. External binaries, downloads, runtime
                probing, and remote target execution are disabled.
              </p>
              <div className="provision-grid">
                <article className="provision-card">
                  <h4>Allowed Activity</h4>
                  <p className="muted-text">Static analysis of local folders, secure coding rules, dependency manifest review.</p>
                </article>
                <article className="provision-card">
                  <h4>Blocked Activity</h4>
                  <p className="muted-text">No website scans, no IP scans, no crawler traffic, no binary bootstrap, no shell download actions.</p>
                </article>
                <article className="provision-card">
                  <h4>Reset Scope</h4>
                  <p className="muted-text">Use reset only to clear local app state, cached reports, and UI state.</p>
                </article>
              </div>
            </div>
          </>
        )}

        <div className="subpanel">
          <h3>Analyzer Policy Logs</h3>
          <div className="log-console">
            {toolActionLogs.length > 0 ? (
              toolActionLogs.map((line, index) => (
                <div key={`${index}-${line}`} className="log-line">
                  {line}
                </div>
              ))
            ) : (
              <p className="muted-text">No analyzer policy events yet.</p>
            )}
          </div>
        </div>
      </section>
    );
  };

  const globeMode = showLanding && landingTransition !== "to-app" ? "landing" : "platform";

  return (
    <div
      className={`scene-shell ${showLanding ? "scene-shell-landing" : "scene-shell-platform"} ${
        landingTransition !== "idle" ? `scene-shell-${landingTransition}` : ""
      }`}
    >
      <GlobeBackdrop mode={globeMode} />
      <div className="scene-noise" aria-hidden="true" />
      <header className="window-chrome">
        <div className="window-chrome-brand">
          <AppBrandIcon
            wrapperClassName="window-chrome-mark"
            fallbackClassName="window-chrome-mark-svg"
          />
          <div className="window-chrome-copy">
            <strong>CodeSentinelX</strong>
            {!showLanding && (
              <div className="window-chrome-menu" aria-label="Application menu" ref={windowMenuRef}>
                {WINDOW_MENU_ITEMS.map((item) => (
                  <div key={item.key} className={`window-menu-item ${activeWindowMenu === item.key ? "is-open" : ""}`}>
                    <button
                      type="button"
                      className="window-menu-button"
                      onClick={() => toggleWindowMenu(item.key)}
                      aria-haspopup="menu"
                      aria-expanded={activeWindowMenu === item.key}
                    >
                      {item.label}
                    </button>
                    {activeWindowMenu === item.key && (
                      <div className="window-menu-dropdown" role="menu" aria-label={`${item.label} menu`}>
                        {windowMenuActions[item.key].map((action) => (
                          <button
                            key={action.label}
                            type="button"
                            className="window-menu-dropdown-item"
                            disabled={action.disabled}
                            onClick={async () => {
                              closeWindowMenu();
                              await action.onSelect();
                            }}
                          >
                            {action.label}
                          </button>
                        ))}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
        <div className="window-drag-region" aria-hidden="true" />
        <div className="window-controls">
          <button type="button" className="window-control window-control-minimize" onClick={() => void window.codeSentinelX.minimizeWindow()} aria-label="Minimize window">
            <span />
          </button>
          <button type="button" className="window-control window-control-maximize" onClick={() => void window.codeSentinelX.toggleMaximizeWindow()} aria-label="Maximize or restore window">
            <span />
          </button>
          <button type="button" className="window-control window-control-close" onClick={() => void window.codeSentinelX.closeWindow()} aria-label="Close window">
            <span />
          </button>
        </div>
      </header>
      <section
        className={`landing-layer ${showLanding ? "is-active" : ""} ${
          landingTransition === "to-app" ? "is-exiting" : ""
        } ${landingTransition === "to-landing" ? "is-entering" : ""}`}
      >
        <LandingPage onEnter={openPlatform} />
      </section>
      <section
        className={`app-layer ${!showLanding ? "is-active" : ""} ${
          landingTransition === "to-app" ? "is-entering" : ""
        } ${landingTransition === "to-landing" ? "is-exiting" : ""}`}
      >
        <div className="app-shell app-stage">
      <aside className="sidebar">
        <div className="brand panel">
          <div className="brand-header">
            <AppBrandIcon
              wrapperClassName="brand-mark"
              fallbackClassName="brand-mark-svg"
            />
            <div>
              <p className="brand-eyebrow">CODESENTINEL X</p>
              <h1>Secure Code Analysis</h1>
            </div>
          </div>
          <p>Inspect every file. Prioritize real code risk.</p>
          <div className="button-row brand-actions">
            <button type="button" onClick={reopenLanding}>
              Welcome Screen
            </button>
          </div>
        </div>

        <nav className="panel nav">
          {visibleTabs.map((item, index) => (
            <button
              key={item.key}
              type="button"
              className={tab === item.key ? "nav-active" : ""}
              onClick={() => setTab(item.key)}
              title={`Shortcut: Alt+${index + 1}`}
            >
              <span className="nav-icon">{item.icon}</span>
              <span className="nav-label">{item.label}</span>
              <kbd className="shortcut-hint">Alt+{index + 1}</kbd>
            </button>
          ))}
        </nav>

        <section className="panel status-panel">
          <h3>Live Scan Status</h3>
          <p className="status-headline">
            {isScanning ? `${activeScanSessions.filter((item) => item.status === "running" || item.status === "paused").length} active scan(s)` : "Scan status"}
          </p>
          <p className="status-summary">{statusText}</p>
          <div className="progress-track">
            <div
              className={`progress-fill ${isFinalizingPhase ? "progress-fill-finalizing" : ""}`}
              style={{ width: `${Math.min(100, Math.max(0, displayProgress))}%` }}
            />
          </div>
          <p className="status-percent">{displayProgress.toFixed(1)}%</p>
          {(scanStatus === "running" || scanStatus === "paused") && (
            <p className="status-runtime">
              {scanStatus === "paused" ? "Paused" : "Running"} for {formatDuration(selectedSessionElapsed)} | Last update {formatDuration(secondsSinceProgressUpdate)} ago
            </p>
          )}
          {isFinalizingPhase && (
            <p className="status-finalizing">
              Finalizing evidence and reports. Scan is still running...
            </p>
          )}
          {activeScanSessions.length > 0 && (
            <div className="session-list">
              <p className="session-list-label">Scan Sessions</p>
              {activeScanSessions.slice(0, 8).map((session) => {
                const live = session.status === "running" || session.status === "paused";
                return (
                  <button
                    key={session.scanId}
                    type="button"
                    className={`session-chip ${activeScanId === session.scanId ? "session-chip-active" : ""}`}
                    onClick={() => setActiveScanId(session.scanId)}
                    title={session.target}
                  >
                    <span className="session-chip-main">{session.scanId.slice(0, 8)}</span>
                    <span className="session-chip-meta">
                      {live ? "live" : session.status} | {session.progress.toFixed(0)}%
                    </span>
                  </button>
                );
              })}
            </div>
          )}
          <div className="mini-log-list">
            {scanLogs.slice(0, 6).map((line, index) => (
              <div key={`${index}-${line}`} className="mini-log-line">
                {line}
              </div>
            ))}
            {scanLogs.length === 0 && <p className="muted-text">No events yet.</p>}
          </div>
          {!scan && lastCompletedScanId && (
            <div className="button-row">
              <button type="button" onClick={reopenLastCompletedScan}>
                Reopen Last Completed Scan ({lastCompletedScanId.slice(0, 8)})
              </button>
            </div>
          )}
          <p className="shortcut-guide">
            Navigation: Alt+1..{Math.max(1, visibleTabs.length)} for main tabs, 1..9 for section tabs.
          </p>
        </section>

        <section className="panel exports">
          <h3>Exports</h3>
          <div className="role-export-card">
            <div className="role-export-header">
              <div>
                <p className="muted-text">Role-selected export scope</p>
                <h4>{selectedRoleExport.title}</h4>
                <p>{selectedRoleExport.description}</p>
              </div>
              <div className="role-export-badge">
                <span>Role</span>
                <strong>{role}</strong>
                <small>{selectedRoleExport.scopeLabel}</small>
              </div>
            </div>

            <ul className="role-export-notes">
              {selectedRoleExport.scopeDetails.map((item) => (
                <li key={item}>{item}</li>
              ))}
            </ul>

            {scan && (
              <div className="projection-audit-card">
                <p className="status-success">
                  One canonical scan is loaded. Switching roles changes this projection only and does not rerun analyzers.
                </p>
                {scan.projection && (
                  <>
                    <p>
                      <strong>Projection:</strong> {scan.projection.visibility} | {scan.projection.projection_reason}
                    </p>
                    <p>
                      <strong>Included:</strong> {scan.projection.inclusion_policy}
                    </p>
                    <p>
                      <strong>Redaction:</strong> {scan.projection.redaction_policy}
                    </p>
                  </>
                )}
              </div>
            )}

            {selectedRoleExport.reportType === "vulnerability" && (
              <div className="report-style-row">
                <span className="muted-text">Findings Report Style</span>
                <div className="report-style-toggle">
                  <button
                    type="button"
                    className={vulnerabilityReportStyle === "classic" ? "active" : ""}
                    onClick={() => setVulnerabilityReportStyle("classic")}
                  >
                    Classic
                  </button>
                  <button
                    type="button"
                    className={vulnerabilityReportStyle === "modern" ? "active" : ""}
                    onClick={() => setVulnerabilityReportStyle("modern")}
                  >
                    Modern (Beta)
                  </button>
                </div>
              </div>
            )}

            <div className="role-export-actions">
              {selectedRoleExport.formats.map((item) => (
                <button
                  key={item.format}
                  type="button"
                  className="role-export-action"
                  title={item.helper}
                  onClick={() => exportReport(item.format)}
                  disabled={!scan || isExporting}
                >
                  <span>{item.label}</span>
                  <small>{item.helper}</small>
                </button>
              ))}
            </div>

            <div className="button-row role-export-footer">
              <button type="button" onClick={() => previewReport()} disabled={!scan || isPreviewLoading}>
                {selectedRoleExport.previewLabel}
              </button>
              <button type="button" onClick={openLastExport} disabled={!lastExport}>
                Open Last Export
              </button>
            </div>
          </div>
        </section>
      </aside>

      <main className="workspace">
        <header className="panel header">
          <div className="header-row">
            <label htmlFor="projectPath">Codebase File or Folder</label>
            <input
              id="projectPath"
              value={projectPath}
              onChange={(event) => setProjectPath(event.target.value)}
              placeholder="C:\\projects\\critical-app"
            />
            <button type="button" onClick={browseProject}>
              Browse
            </button>
            <button
              type="button"
              onClick={runScan}
              disabled={!roleCaps.canRunScan}
              title={!roleCaps.canRunScan ? `Role ${role} cannot start scans.` : ""}
            >
              {isScanning ? `Canonical Scan (+${activeScanSessions.filter((item) => item.status === "running" || item.status === "paused").length} live)` : "Run Canonical Scan"}
            </button>
            <select
              value={scanPreset}
              aria-label="Canonical scan preset"
              title={`Canonical one-scan preset: ${SCAN_PRESETS.find((item) => item.key === scanPreset)?.helper || "Scan preset"}`}
              onChange={(event) => setScanPreset(event.target.value as ScanPreset)}
              disabled={isScanning}
            >
              {SCAN_PRESETS.map((item) => (
                <option key={item.key} value={item.key}>
                  {item.label}
                </option>
              ))}
            </select>
            <div className="scan-controls">
              <button
                type="button"
                onClick={pauseScan}
                disabled={!selectedActiveSession || selectedActiveSession.status !== "running" || !roleCaps.canRunScan}
                title={!roleCaps.canRunScan ? `Role ${role} cannot control scans.` : "Pause active scan"}
              >
                || Pause
              </button>
              <button
                type="button"
                onClick={resumeScan}
                disabled={!selectedActiveSession || selectedActiveSession.status !== "paused" || !roleCaps.canRunScan}
                title={!roleCaps.canRunScan ? `Role ${role} cannot control scans.` : "Resume paused scan"}
              >
                {" > Resume"}
              </button>
              <button
                type="button"
                onClick={stopScan}
                disabled={!selectedActiveSession || !roleCaps.canRunScan}
                title={!roleCaps.canRunScan ? `Role ${role} cannot control scans.` : "Stop active scan"}
              >
                [] Stop
              </button>
            </div>
            <select
              value={role}
              onChange={(event) => setRole(event.target.value as UserRole)}
              title={roleDrilldownSummary(role)}
              aria-label="Operator role"
            >
              {ROLES.map((item) => (
                <option value={item} key={item}>
                  {item}
                </option>
              ))}
            </select>
            {toolAuthEnabled && !toolSessionValid && canOpenOwnerLogin && (
              <button type="button" onClick={() => setShowOwnerAccessPanel((previous) => !previous)}>
                {showOwnerAccessPanel ? "Close Owner Access" : "Owner Login"}
              </button>
            )}
          </div>
          <div className="scm-toggle-row">
            <button type="button" className={showScmOptions ? "active" : ""} onClick={() => setShowScmOptions((previous) => !previous)}>
              {showScmOptions ? "Hide PR/MR Differential Options" : "Show PR/MR Differential Options (Optional)"}
            </button>
            <span className="muted-text">
              Use these fields only for differential scans between base/head commits or a changed-files manifest.
            </span>
            {hasScmContext && <span className="scm-configured-pill">Configured</span>}
          </div>
          {showScmOptions && (
            <div className="header-row scm-row">
              <label htmlFor="diffBaseRef">Diff Base</label>
              <input
                id="diffBaseRef"
                value={diffBaseRef}
                onChange={(event) => setDiffBaseRef(event.target.value)}
                placeholder="Optional: origin/main or base commit SHA"
              />
              <label htmlFor="diffHeadRef">Diff Head</label>
              <input
                id="diffHeadRef"
                value={diffHeadRef}
                onChange={(event) => setDiffHeadRef(event.target.value)}
                placeholder="Optional: HEAD or head commit SHA"
              />
              <label htmlFor="changedFilesManifestPath">Changed Files Manifest</label>
              <input
                id="changedFilesManifestPath"
                value={changedFilesManifestPath}
                onChange={(event) => setChangedFilesManifestPath(event.target.value)}
                placeholder="Optional: path to JSON/newline changed files list"
              />
            </div>
          )}
          <p className="target-mode">Mode: Codebase Secure Analysis</p>
          <p className="role-hint">
            Scan preset ({scanPreset}): {SCAN_PRESETS.find((item) => item.key === scanPreset)?.helper}
          </p>
          <p className="role-hint">
            Role Drill-Down ({role}): {roleDrilldownSummary(role)}
          </p>
          <p className="role-hint">
            This role will show: {ROLE_SCAN_SCOPE[role].join(", ")}. The scanner runs once and stores a canonical scan; role changes only redraw the view/export projection.
          </p>
          <p className="role-hint">Severity policy: {ROLE_SEVERITY_POLICY[role]}</p>
          <p className="role-hint">
            Access: scan={roleCaps.canRunScan ? "yes" : "no"} | review={roleCaps.canReviewFindings ? "yes" : "no"} |
            catalog={roleCaps.canManageTools ? "manage" : "read-only"} | reset={roleCaps.canProvisionTools ? "yes" : "no"}
          </p>
          {toolAuthEnabled && (
            <p className="role-hint">
              Analyzer Catalog owner lock: {toolSessionValid ? "verified" : "locked"} | {toolAuthConfig?.message || ""}
            </p>
          )}
          <div className="report-switch">
            <button
              type="button"
              className={tab === "vulnerabilities" ? "active" : ""}
              onClick={() => setTab("vulnerabilities")}
            >
              Code Findings
            </button>
            <button
              type="button"
              className={tab === "existing" ? "active" : ""}
              onClick={() => setTab("existing")}
            >
              Secure Coding Practices
            </button>
            <button type="button" className={tab === "dashboard" ? "active" : ""} onClick={() => setTab("dashboard")}>
              Code Risk Overview
            </button>
            {isToolManagerVisible && (
              <button type="button" className={tab === "tools" ? "active" : ""} onClick={() => setTab("tools")}>
                Analyzer Catalog
              </button>
            )}
          </div>
          <div className="status-row">
            <span>{statusText}</span>
            <div className="progress-wrap">
              <div className="progress-track">
                <div
                  className={`progress-fill ${isFinalizingPhase ? "progress-fill-finalizing" : ""}`}
                  style={{ width: `${Math.min(100, Math.max(0, displayProgress))}%` }}
                />
              </div>
              <span>{displayProgress.toFixed(1)}%</span>
            </div>
          </div>
          {isFinalizingPhase && <p className="status-finalizing">Finalizing scan output. Processing is still active.</p>}
          {(scanStatus === "running" || scanStatus === "paused") && (
            <p className="status-runtime">
              {scanStatus === "paused" ? "Paused" : "Running"} for {formatDuration(selectedSessionElapsed)} | Last update {formatDuration(secondsSinceProgressUpdate)} ago
            </p>
          )}
          {lastExport && <p className="export-path">Last export: {lastExport}</p>}
        </header>

        {(isPreviewLoading || reportPreviewSrc) && (
          <section className="panel preview-dock">
            <div className="preview-dock-head">
              <h3>
                Report Preview
                {previewReportType ? ` | ${previewReportType.toUpperCase()}` : ""}
                {previewReportType === "vulnerability" ? ` | ${vulnerabilityReportStyle.toUpperCase()}` : ""}
              </h3>
              <div className="button-row">
                <button type="button" onClick={closePreview}>
                  Close Preview
                </button>
              </div>
            </div>
            {isPreviewLoading ? (
              <p className="muted-text">Rendering preview...</p>
            ) : (
              <iframe
                className="report-preview-frame"
                srcDoc={reportPreviewSrc}
                title="CodeSentinelX Report Preview"
                sandbox="allow-same-origin allow-scripts"
              />
            )}
          </section>
        )}

        {toolAuthEnabled && !toolSessionValid && canOpenOwnerLogin && showOwnerAccessPanel && renderOwnerAccessPanel()}

            {tab === "dashboard" && renderDashboard()}
            {tab === "threat-model" && renderThreatModel()}
            {tab === "existing" && renderExistingReport()}
        {tab === "vulnerabilities" && renderVulnerabilityReport()}
        {tab === "compliance" && renderCompliance()}
        {tab === "history" && renderHistory()}
        {tab === "tools" && renderToolManager()}
        {tab === "help" && renderHelp()}
      </main>
        </div>
      </section>
    </div>
  );
}

function LandingPage(props: { onEnter: () => void }): React.JSX.Element {
  const scrollToOverview = (event: React.MouseEvent<HTMLAnchorElement>) => {
    event.preventDefault();
    document.getElementById("landing-overview")?.scrollIntoView({ behavior: "smooth", block: "start" });
  };

  return (
    <div className="landing-screen">
      <header className="landing-topbar">
        <div className="landing-brand">
          <AppBrandIcon
            wrapperClassName="landing-brand-mark"
            fallbackClassName="landing-brand-svg"
          />
          <div>
            <p className="landing-brand-tag">CodeSentinelX</p>
            <p className="landing-brand-subtitle">Enterprise Secure Code Analysis</p>
          </div>
        </div>
      </header>

      <section className="landing-hero">
        <div className="landing-hero-copy">
          <p className="landing-overline">Welcome to</p>
          <h1>
            <span>CodeSentinelX</span>
            <strong>Secure Code Analysis</strong>
          </h1>
          <p className="landing-hero-note">Grounded code intelligence for engineering, AppSec, and leadership teams.</p>
          <div className="landing-cta-row">
            <button type="button" className="landing-primary-cta" onClick={props.onEnter}>
              Launch Workspace
            </button>
            <a href="#landing-overview" className="landing-secondary-link" onClick={scrollToOverview}>
              Know more
            </a>
          </div>
        </div>
      </section>

      <section className="landing-highlight-stack">
        {LANDING_HIGHLIGHTS.map((item) => (
          <p key={item} className="landing-highlight-line">
            {item}
          </p>
        ))}
      </section>

      <section id="landing-overview" className="landing-section">
        <div className="landing-section-head">
          <p className="landing-section-tag">Overview</p>
          <h2>Know more about what the platform actually does</h2>
        </div>
        <div className="landing-feature-grid">
          {LANDING_FEATURES.map((item) => (
            <article key={item.title} className="landing-feature-card">
              <h3>{item.title}</h3>
              <p>{item.body}</p>
            </article>
          ))}
        </div>
      </section>

      <section className="landing-section">
        <div className="landing-section-head">
          <p className="landing-section-tag">Advantages</p>
          <h2>Built to be useful across engineering, AppSec, and leadership</h2>
        </div>
        <div className="landing-advantage-grid">
          {LANDING_ADVANTAGES.map((item) => (
            <article key={item.label} className="landing-advantage-card">
              <p>{item.label}</p>
              <h3>{item.value}</h3>
            </article>
          ))}
        </div>
      </section>

      <section className="landing-section landing-story-grid">
        <article className="landing-story-card">
          <p className="landing-section-tag">Feature importance</p>
          <h3>Why this matters in real use</h3>
          <ul className="landing-story-list">
            <li>Developers get file, line, evidence, and fix direction without hunting through raw analysis logs.</li>
            <li>Security analysts can work from code-context findings instead of generic risk labels.</li>
            <li>Leadership gets export-ready reporting that explains risk in a cleaner, more operational way.</li>
          </ul>
        </article>
        <article className="landing-story-card">
          <p className="landing-section-tag">Uniqueness</p>
          <h3>What stands out from generic tools</h3>
          <ul className="landing-story-list">
            <li>Codebase-only focus keeps the product aligned to secure coding and internal review workflows.</li>
            <li>Evidence replay, integrity reporting, and fix verification hooks help prove authenticity.</li>
            <li>Optional grounded AI is layered on top of source evidence instead of replacing it.</li>
          </ul>
        </article>
      </section>
    </div>
  );
}

function SubTabs(props: {
  tabs: Array<{ key: string; label: string; icon?: string }>;
  active: string;
  onChange: (value: string) => void;
}): React.JSX.Element {
  return (
    <div className="section-tabs">
      {props.tabs.map((tab, index) => (
        <button
          key={tab.key}
          type="button"
          className={props.active === tab.key ? "active" : ""}
          onClick={() => props.onChange(tab.key)}
          title={`Shortcut: ${index + 1}`}
        >
          <span className="subtab-icon">{tab.icon || "SB"}</span>
          {tab.label}
          <kbd className="shortcut-hint">{index + 1}</kbd>
        </button>
      ))}
    </div>
  );
}

function MetricCard(props: { label: string; value: string }): React.JSX.Element {
  return (
    <article className="metric-card">
      <p>{props.label}</p>
      <h4>{props.value}</h4>
    </article>
  );
}

function EmptyState(props: { text: string }): React.JSX.Element {
  return (
    <section className="empty-state">
      <p>{props.text}</p>
    </section>
  );
}
