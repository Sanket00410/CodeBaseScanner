import React, { useEffect, useMemo, useState } from "react";

import {
  AuditLogEntry,
  ProfileComplianceReport,
  ResetLocalStateCacheResult,
  ScanHistoryItem,
  ScanView,
  Severity,
  ToolActionResult,
  ToolBootstrapMode,
  ToolBootstrapResult,
  ToolCatalogItem,
  ToolScanProfile,
  ToolchainStatusEntry,
  UserRole,
  VulnerabilityFinding,
} from "./types";

type AppTab = "dashboard" | "existing" | "vulnerabilities" | "compliance" | "history" | "tools";
type ExportFormat = "json" | "html" | "pdf" | "sarif" | "csv" | "patch";
type ExportType = "existing" | "vulnerability" | "fixes" | "combined";
type DashboardSection = "overview" | "toolchain" | "assets" | "operations";
type ExistingSection = "summary" | "controls" | "compliance";
type VulnerabilitySection = "queue" | "detail";
type ComplianceSection = "profile" | "matrix" | "actions";
type HistorySection = "scans" | "audits";
type ToolManagerSection = "codebase" | "website" | "ip" | "roles" | "provisioning";
type RoleCapabilities = {
  canRunScan: boolean;
  canReviewFindings: boolean;
  canCopyFixes: boolean;
  canManageTools: boolean;
  canProvisionTools: boolean;
};

const TABS: Array<{ key: AppTab; label: string; icon: string; shortcut: string }> = [
  { key: "dashboard", label: "Dashboard", icon: "CM", shortcut: "1" },
  { key: "existing", label: "Existing Security Report", icon: "ES", shortcut: "2" },
  { key: "vulnerabilities", label: "Vulnerability Report", icon: "VR", shortcut: "3" },
  { key: "compliance", label: "Compliance", icon: "CP", shortcut: "4" },
  { key: "history", label: "Scan History", icon: "HS", shortcut: "5" },
  { key: "tools", label: "Tool Manager", icon: "TM", shortcut: "6" },
];

const ROLES: UserRole[] = ["Admin", "Security Analyst", "Developer", "Auditor"];
const SEVERITY_ORDER: Severity[] = ["Critical", "High", "Medium", "Low", "Info"];
const TOOL_PROFILES: ToolScanProfile[] = ["codebase", "website", "ip"];

const TOOL_PROFILE_META: Record<ToolScanProfile, { label: string; icon: string; helper: string }> = {
  codebase: {
    label: "Codebase Tools",
    icon: "CB",
    helper: "Use for local folders, repositories, and SSH codebase paths.",
  },
  website: {
    label: "Website Tools",
    icon: "WS",
    helper: "Use for HTTP/HTTPS application targets and localhost runtime scans.",
  },
  ip: {
    label: "IP/Network Tools",
    icon: "IP",
    helper: "Use for host/IP attack-surface and network exposure checks.",
  },
};

const ROLE_DRILLDOWN: Array<{ role: UserRole; purpose: string; drillDownUse: string; primaryActions: string }> = [
  {
    role: "Admin",
    purpose: "Govern platform policies and team-level risk posture.",
    drillDownUse: "Escalate from executive trends into cross-project critical findings and ownership.",
    primaryActions: "Policy changes, baseline updates, toolchain provisioning, exception approvals.",
  },
  {
    role: "Security Analyst",
    purpose: "Triage and validate findings with security context.",
    drillDownUse: "Pivot from module/file counts to exact evidence and exploitability before routing work.",
    primaryActions: "Triage, severity validation, false-positive suppression, handoff to developers.",
  },
  {
    role: "Developer",
    purpose: "Fix vulnerable code with minimal context switching.",
    drillDownUse: "Jump directly from finding row to file/line, original code, and suggested fix.",
    primaryActions: "Patch implementation, review status updates, regression-safe remediation.",
  },
  {
    role: "Auditor",
    purpose: "Produce evidence and compliance-ready reporting.",
    drillDownUse: "Trace each metric back to concrete findings, ownership, and export artifacts.",
    primaryActions: "Audit evidence capture, control verification, export sign-off packages.",
  },
];

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
    canReviewFindings: false,
    canCopyFixes: true,
    canManageTools: false,
    canProvisionTools: false,
  },
  Auditor: {
    canRunScan: false,
    canReviewFindings: false,
    canCopyFixes: false,
    canManageTools: false,
    canProvisionTools: false,
  },
};

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

function normalizeFindingPath(value: string): string {
  return String(value || "").replaceAll("\\", "/");
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

function detectTargetMode(value: string): "codebase" | "runtime-ip" {
  const target = value.trim();
  if (!target) {
    return "codebase";
  }
  if (/^ssh:\/\//i.test(target)) {
    return "codebase";
  }
  if (/^https?:\/\//i.test(target)) {
    return "runtime-ip";
  }
  if (/^\d{1,3}(\.\d{1,3}){3}(:\d+)?(\/.*)?$/.test(target)) {
    return "runtime-ip";
  }
  if (/^localhost(:\d+)?(\/.*)?$/i.test(target)) {
    return "runtime-ip";
  }
  if (/^[a-z0-9.-]+\.[a-z]{2,}(:\d+)?(\/.*)?$/i.test(target)) {
    return "runtime-ip";
  }
  return "codebase";
}

function normalizeToolEntry(tool: string, info: ToolchainStatusEntry): ToolchainStatusEntry {
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
  const explicit = (tool.scan_profiles || []).filter((profile): profile is ToolScanProfile =>
    TOOL_PROFILES.includes(profile as ToolScanProfile),
  );
  if (explicit.length > 0) {
    return [...new Set(explicit)];
  }

  const profiles = new Set<ToolScanProfile>();
  const modes = new Set(tool.target_modes || []);
  if (modes.has("codebase") || modes.has("remote-codebase")) {
    profiles.add("codebase");
  }
  if (modes.has("runtime")) {
    profiles.add("website");
    const category = String(tool.category || "").toLowerCase();
    const name = String(tool.name || "").toLowerCase();
    if (
      category.includes("network") ||
      category.includes("attack surface") ||
      category.includes("kubernetes") ||
      ["nmap", "amass", "kube-bench", "kube-hunter", "runtime_http_probe"].includes(name)
    ) {
      profiles.add("ip");
    }
  }
  return [...profiles];
}

function roleDrilldownSummary(role: UserRole): string {
  const item = ROLE_DRILLDOWN.find((entry) => entry.role === role);
  if (!item) {
    return "";
  }
  return `${item.purpose} ${item.drillDownUse}`;
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

export default function App(): React.JSX.Element {
  const [tab, setTab] = useState<AppTab>("dashboard");
  const [projectPath, setProjectPath] = useState("");
  const [role, setRole] = useState<UserRole>("Security Analyst");
  const [isScanning, setIsScanning] = useState(false);
  const [statusText, setStatusText] = useState("Ready");
  const [progress, setProgress] = useState(0);
  const [scan, setScan] = useState<ScanView | null>(null);
  const [history, setHistory] = useState<ScanHistoryItem[]>([]);
  const [audits, setAudits] = useState<AuditLogEntry[]>([]);
  const [lastExport, setLastExport] = useState("");
  const [reportPreviewHtml, setReportPreviewHtml] = useState("");
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
  const [searchText, setSearchText] = useState("");
  const [selectedFindingId, setSelectedFindingId] = useState("");
  const [toolCatalog, setToolCatalog] = useState<ToolCatalogItem[]>([]);
  const [toolSearchText, setToolSearchText] = useState("");
  const [toolBusyKey, setToolBusyKey] = useState("");
  const [toolActionLogs, setToolActionLogs] = useState<string[]>([]);
  const roleCaps = useMemo(() => ROLE_CAPABILITIES[role], [role]);

  const findings = useMemo(() => {
    if (!scan) {
      return [];
    }
    return sortFindings(scan.report.vulnerability_fixed_code_report.findings || []);
  }, [scan]);

  const filteredFindings = useMemo(() => {
    const query = searchText.trim().toLowerCase();
    return findings.filter((item) => {
      if (severityFilter !== "All" && item.severity !== severityFilter) {
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
      ]
        .join(" ")
        .toLowerCase();
      return text.includes(query);
    });
  }, [findings, searchText, severityFilter]);

  const affectedFiles = useMemo(() => aggregateFindingsByFile(findings), [findings]);
  const affectedFolders = useMemo(() => aggregateFindingsByFolder(findings), [findings]);
  const profileCompliance = useMemo(() => resolveProfileCompliance(scan), [scan]);
  const targetMode = useMemo(() => detectTargetMode(projectPath), [projectPath]);
  const toolchainEntries = useMemo<ToolchainStatusEntry[]>(() => {
    if (!scan) {
      return [];
    }
    const entries = Object.entries(scan.report.vulnerability_fixed_code_report.toolchain_status || {}).map(([tool, info]) =>
      normalizeToolEntry(tool, info),
    );
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
    return toolCatalog.map((tool) => {
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
  const activeToolProfile = useMemo<ToolScanProfile>(() => {
    if (toolSection === "codebase" || toolSection === "website" || toolSection === "ip") {
      return toolSection;
    }
    return targetMode === "runtime-ip" ? "website" : "codebase";
  }, [toolSection, targetMode]);
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
      website: { total: 0, ready: 0, integrated: 0 },
      ip: { total: 0, ready: 0, integrated: 0 },
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

  useEffect(() => {
    const dispose = window.codeSentinelX.onScanProgress((payload) => {
      const filePart = payload.currentFile ? ` | ${payload.currentFile}` : "";
      setStatusText(`${payload.stage}${filePart} | ${payload.message}`);
      setProgress(payload.progress);
      const time = new Date().toLocaleTimeString();
      const line = `[${time}] ${payload.stage}${filePart} | ${payload.message}`;
      setScanLogs((previous) => [line, ...previous].slice(0, 300));
    });
    return () => dispose();
  }, []);

  useEffect(() => {
    loadHistory().catch((error) => setStatusText(`History load failed: ${String(error)}`));
    loadAudits().catch(() => undefined);
    loadTools().catch((error) => setStatusText(`Tool catalog load failed: ${String(error)}`));
  }, []);

  useEffect(() => {
    if (selectedFinding && selectedFinding.finding_uid !== selectedFindingId) {
      setSelectedFindingId(selectedFinding.finding_uid);
    }
  }, [selectedFinding, selectedFindingId]);

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
        const targetTab = TABS[index];
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
        const items: HistorySection[] = ["scans", "audits"];
        if (items[index]) {
          event.preventDefault();
          setHistorySection(items[index]);
        }
        return;
      }
      if (tab === "tools") {
        const items: ToolManagerSection[] = ["codebase", "website", "ip", "roles", "provisioning"];
        if (items[index]) {
          event.preventDefault();
          setToolSection(items[index]);
        }
      }
    };

    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [tab]);

  const loadHistory = async (): Promise<void> => {
    const items = await window.codeSentinelX.getScanHistory();
    setHistory(items);
  };

  const loadAudits = async (scanId?: string): Promise<void> => {
    const items = await window.codeSentinelX.listAuditLogs(scanId);
    setAudits(items);
  };

  const loadTools = async (): Promise<void> => {
    const tools = await window.codeSentinelX.listTools();
    setToolCatalog(tools);
  };

  const browseProject = async (): Promise<void> => {
    const picked = await window.codeSentinelX.pickProjectFolder();
    if (picked) {
      setProjectPath(picked);
    }
  };

  const runScan = async (): Promise<void> => {
    if (!roleCaps.canRunScan) {
      setStatusText(`Role ${role} does not have permission to start scans.`);
      return;
    }
    if (!projectPath.trim()) {
      setStatusText("Select a project folder before scanning.");
      return;
    }
    setIsScanning(true);
    setProgress(0);
    setReportPreviewHtml("");
    setPreviewReportType("");
    setScanLogs([]);
    setStatusText(targetMode === "runtime-ip" ? "Submitting runtime/remote scan..." : "Submitting codebase scan...");
    try {
      const result = await window.codeSentinelX.startScan({
        projectPath,
        requestedBy: "local-user",
        role,
      });
      setScan(result);
      setTab("dashboard");
      setStatusText("Scan completed");
      setProgress(100);
      setSelectedFindingId("");
      await Promise.all([loadHistory(), loadAudits(result.scanId)]);
    } catch (error) {
      setStatusText(`Scan failed: ${String(error)}`);
    } finally {
      setIsScanning(false);
    }
  };

  const openScan = async (scanId: string): Promise<void> => {
    const result = await window.codeSentinelX.getScanById(scanId);
    if (!result) {
      setStatusText(`Scan ${scanId} not found.`);
      return;
    }
    setScan(result);
    setStatusText(`Loaded scan ${scanId.slice(0, 8)}`);
    setProgress(100);
    setSelectedFindingId("");
    await loadAudits(scanId);
  };

  const markReviewed = async (findingId: string): Promise<void> => {
    if (!roleCaps.canReviewFindings) {
      setStatusText(`Role ${role} cannot mark findings as reviewed.`);
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
      setStatusText("Finding marked as reviewed.");
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
      setStatusText("No patch preview available for this finding.");
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

  const exportReport = async (reportType: ExportType, format: ExportFormat): Promise<void> => {
    if (!scan) {
      setStatusText("No scan loaded for export.");
      return;
    }
    const output = await window.codeSentinelX.exportReport({
      scanId: scan.scanId,
      reportType,
      format,
    });
    setLastExport(output);
    setStatusText(`Exported ${reportType} report as ${format}`);
    await loadAudits(scan.scanId);
  };

  const previewReport = async (reportType: ExportType): Promise<void> => {
    if (!scan) {
      setStatusText("Run a scan before previewing reports.");
      return;
    }
    setIsPreviewLoading(true);
    setPreviewReportType(reportType);
    try {
      const html = await window.codeSentinelX.renderReportHtml({ scanId: scan.scanId, reportType });
      setReportPreviewHtml(html);
      setStatusText(`Loaded ${reportType} report preview.`);
      setTab("dashboard");
    } catch (error) {
      setPreviewReportType("");
      setStatusText(`Failed to render preview: ${String(error)}`);
    } finally {
      setIsPreviewLoading(false);
    }
  };

  const closePreview = (): void => {
    setReportPreviewHtml("");
    setPreviewReportType("");
    setIsPreviewLoading(false);
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

  const appendToolActionLog = (label: string, result: ToolActionResult): void => {
    const stamp = new Date().toLocaleTimeString();
    const status = result.success ? "SUCCESS" : "FAILED";
    const output = result.outputPath ? ` | output=${result.outputPath}` : "";
    const line = `[${stamp}] ${label} ${result.tool} => ${status} | ${result.message}${output}`;
    setToolActionLogs((previous) => [line, ...previous].slice(0, 200));
  };

  const runToolAction = async (
    key: string,
    action: () => Promise<ToolActionResult>,
    successMessage: string,
  ): Promise<void> => {
    setToolBusyKey(key);
    try {
      const result = await action();
      appendToolActionLog(key, result);
      if (result.outputPath) {
        setLastExport(result.outputPath);
      }
      if (!result.success) {
        setStatusText(`Tool action failed: ${result.message}`);
      } else {
        setStatusText(`${successMessage} ${result.message}`);
      }
      await Promise.all([loadTools(), loadAudits()]);
    } catch (error) {
      setStatusText(`Tool action error: ${String(error)}`);
    } finally {
      setToolBusyKey("");
    }
  };

  const checkTool = async (toolName: string): Promise<void> => {
    if (!roleCaps.canManageTools) {
      setStatusText(`Role ${role} has read-only access to Tool Manager.`);
      return;
    }
    await runToolAction(
      `check-${toolName}`,
      () => window.codeSentinelX.checkTool({ tool: toolName }),
      "Tool check completed.",
    );
  };

  const installTool = async (toolName: string): Promise<void> => {
    if (!roleCaps.canManageTools) {
      setStatusText(`Role ${role} has read-only access to Tool Manager.`);
      return;
    }
    await runToolAction(
      `install-${toolName}`,
      () => window.codeSentinelX.installTool({ tool: toolName }),
      "Tool install completed.",
    );
  };

  const runSingleTool = async (toolName: string): Promise<void> => {
    if (!roleCaps.canManageTools) {
      setStatusText(`Role ${role} has read-only access to Tool Manager.`);
      return;
    }
    if (!projectPath.trim()) {
      setStatusText("Enter a target path/URL/IP before running a tool.");
      return;
    }
    await runToolAction(
      `run-${toolName}`,
      () => window.codeSentinelX.runTool({ tool: toolName, target: projectPath }),
      "Tool run completed.",
    );
  };

  const appendBootstrapLog = (result: ToolBootstrapResult): void => {
    const stamp = new Date().toLocaleTimeString();
    const status = result.success ? "SUCCESS" : "PARTIAL";
    const summaryLine = `[${stamp}] bootstrap ${result.profile}/${result.mode} => ${status} | ready=${result.ready}/${result.total} | ${result.message}`;
    const issueLines = result.tools
      .filter((item) => !item.available)
      .slice(0, 15)
      .map((item) => `[${stamp}] missing ${item.tool} | ${item.message}`);
    setToolActionLogs((previous) => [summaryLine, ...issueLines, ...previous].slice(0, 300));
  };

  const bootstrapToolsByProfile = async (
    profile: ToolScanProfile | "all",
    mode: ToolBootstrapMode,
    successMessage: string,
  ): Promise<void> => {
    if (!roleCaps.canProvisionTools) {
      setStatusText(`Role ${role} cannot provision toolchains.`);
      return;
    }
    const key = `bootstrap-${profile}-${mode}`;
    setToolBusyKey(key);
    try {
      const result = await window.codeSentinelX.bootstrapTools({ profile, mode });
      appendBootstrapLog(result);
      if (!result.success) {
        setStatusText(`Provisioning completed with gaps: ${result.message}`);
      } else {
        setStatusText(`${successMessage} ${result.message}`);
      }
      await Promise.all([loadTools(), loadAudits()]);
    } catch (error) {
      setStatusText(`Provisioning failed: ${String(error)}`);
    } finally {
      setToolBusyKey("");
    }
  };

  const resetLocalStateCache = async (): Promise<void> => {
    if (!roleCaps.canProvisionTools) {
      setStatusText(`Role ${role} cannot reset local state/cache.`);
      return;
    }
    if (isScanning) {
      setStatusText("Stop the active scan before resetting local state/cache.");
      return;
    }

    const confirmed = window.confirm(
      "Reset local state/cache?\n\nThis will clear scan history, audit state, tool-run cache, and local .toolchain cache for this app profile.",
    );
    if (!confirmed) {
      return;
    }

    const key = "reset-local-state-cache";
    setToolBusyKey(key);
    try {
      const result = (await window.codeSentinelX.resetLocalStateCache()) as ResetLocalStateCacheResult;
      const stamp = new Date().toLocaleTimeString();
      const coreLine = result.coreWarmup
        ? ` | coreWarmup=${result.coreWarmup.ready}/${result.coreWarmup.total} ready, missing=${result.coreWarmup.missing}`
        : "";
      const backupLine = result.storeBackupPath ? ` | backup=${result.storeBackupPath}` : "";
      const cacheLine = result.toolchainCachePath ? ` | cache=${result.toolchainCachePath}` : "";
      const line = `[${stamp}] reset local-state-cache => ${result.success ? "SUCCESS" : "FAILED"} | ${result.message}${coreLine}${cacheLine}${backupLine}`;
      setToolActionLogs((previous) => [line, ...previous].slice(0, 300));

      setScan(null);
      setSelectedFindingId("");
      setProgress(0);
      setLastExport("");
      setReportPreviewHtml("");
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

    return (
      <section className="panel stack-gap">
        <SubTabs
          tabs={[
            { key: "overview", label: "Overview", icon: "OV" },
            { key: "toolchain", label: "Toolchain", icon: "TL" },
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
              <MetricCard label="Raw Findings" value={String(summary.total_vulnerabilities)} />
              <MetricCard label="Deduplicated Findings" value={String(vulnSummary.total_findings)} />
              <MetricCard label="Open Findings" value={String(vulnSummary.open_findings ?? vulnSummary.total_findings)} />
              <MetricCard label="Reviewed Findings" value={String(vulnSummary.reviewed_findings || 0)} />
            </div>

            <div className="severity-strip">
              {SEVERITY_ORDER.map((severity) => (
                <article key={severity} className={`severity-card severity-${severity}`}>
                  <p>{severity}</p>
                  <h4>{vulnSummary.severity_distribution?.[severity] || 0}</h4>
                </article>
              ))}
            </div>

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
                    {(vulnSummary.top_owasp_categories || summary.top_owasp_categories || []).slice(0, 10).map((item) => (
                      <tr key={item.owasp_category}>
                        <td>{item.owasp_category}</td>
                        <td>{item.count}</td>
                      </tr>
                    ))}
                    {(vulnSummary.top_owasp_categories || summary.top_owasp_categories || []).length === 0 && (
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
                    {(vulnSummary.affected_modules || []).slice(0, 10).map((item) => (
                      <tr key={`${item.module}-${item.count}`}>
                        <td>{item.module}</td>
                        <td>{item.count}</td>
                        <td>{item.critical}</td>
                        <td>{item.high}</td>
                      </tr>
                    ))}
                    {(vulnSummary.affected_modules || []).length === 0 && (
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
                  {(summary.recommended_action_plan || []).slice(0, 7).map((item) => (
                    <li key={item}>{item}</li>
                  ))}
                  {(summary.recommended_action_plan || []).length === 0 && <li>No action plan available.</li>}
                </ol>
              </div>
            </div>
          </>
        )}

        {dashboardSection === "toolchain" && (
          <>
            <div className="metric-grid toolchain-metrics">
              <MetricCard label="Catalog Tools" value={String(toolchainEntries.length)} />
              <MetricCard
                label="Selected This Scan"
                value={String(toolchainEntries.filter((item) => item.selected).length)}
              />
              <MetricCard label="Ready Tools" value={String(toolchainEntries.filter((item) => item.available).length)} />
              <MetricCard
                label="Integrated Parsers"
                value={String(toolchainEntries.filter((item) => item.integrated).length)}
              />
              <MetricCard
                label="Runtime-Capable"
                value={String(toolchainEntries.filter((item) => (item.target_modes || []).includes("runtime")).length)}
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
                <h3>Toolchain Status and Coverage</h3>
                <div className="table-scroll">
                  <table className="simple-table toolchain-table">
                    <thead>
                      <tr>
                        <th>Tool</th>
                        <th>Selected</th>
                        <th>Ready</th>
                        <th>Modes</th>
                        <th>Vulnerability Coverage</th>
                        <th>Category</th>
                        <th>Source</th>
                        <th>Command</th>
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
                          <td>{(entry.target_modes || []).join(", ") || "-"}</td>
                          <td>{(entry.vulnerability_classes || []).join(", ") || "-"}</td>
                          <td>{entry.category || "-"}</td>
                          <td>{entry.source || "-"}</td>
                          <td>{entry.command || entry.recommended_command || "-"}</td>
                          <td>{entry.message || "-"}</td>
                        </tr>
                      ))}
                      {toolchainEntries.length === 0 && (
                        <tr>
                          <td colSpan={9}>No toolchain data available.</td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </div>

              <div className="subpanel">
                <h3>Selected Tool Coverage Matrix</h3>
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
              <h3>Report Preview Controls</h3>
              <div className="button-row">
                <button type="button" onClick={() => previewReport("vulnerability")}>
                  Preview Vulnerability
                </button>
                <button type="button" onClick={() => previewReport("existing")}>
                  Preview Existing
                </button>
                <button type="button" onClick={() => previewReport("fixes")}>
                  Preview Fixes
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
            { key: "detail", label: "Finding Detail", icon: "D" },
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
                    <th>CVSS</th>
                    <th>Line</th>
                    <th>Status</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredFindings.map((item) => (
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
                      <td>{(item.cvss_score || 0).toFixed(1)}</td>
                      <td>{item.line_number}</td>
                      <td>{item.status || "Open"}</td>
                    </tr>
                  ))}
                  {filteredFindings.length === 0 && (
                    <tr>
                      <td colSpan={6}>No findings match this filter.</td>
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
                  <strong>Description:</strong> {selectedFinding.description || "No additional description available."}
                </p>
                <p>
                  <strong>Source Tool:</strong> {selectedFinding.tool || "scanner"}
                </p>
                <p>
                  <strong>Business Impact:</strong> {selectedFinding.business_impact}
                </p>
                <p>
                  <strong>Remediation:</strong> {selectedFinding.recommendation}
                </p>
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
                <h4>Patch Preview</h4>
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
                    title={!roleCaps.canReviewFindings ? `Role ${role} cannot mark findings.` : ""}
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
                        {(framework.rows || []).map((row) => (
                          <tr key={`${framework.framework_id}-${row.id}`}>
                            <td>{row.id}</td>
                            <td>{row.title}</td>
                            <td>
                              <span className={`compliance-status compliance-${row.status}`}>
                                {row.status.replaceAll("_", " ")}
                              </span>
                            </td>
                            <td>{row.finding_count}</td>
                            <td>{row.control_count}</td>
                            <td>{row.count}</td>
                          </tr>
                        ))}
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
          ]}
          active={historySection}
          onChange={(value) => setHistorySection(value as HistorySection)}
        />

        {historySection === "scans" && (
          <div className="subpanel">
            <h3>Scan History</h3>
            <table className="simple-table">
              <thead>
                <tr>
                  <th>Scan ID</th>
                  <th>Project</th>
                  <th>Risk</th>
                  <th>Findings</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {history.map((item) => (
                  <tr key={item.scanId}>
                    <td>{item.scanId.slice(0, 8)}</td>
                    <td>{item.projectPath}</td>
                    <td>{item.risk}</td>
                    <td>{item.totalFindings}</td>
                    <td>
                      <button type="button" onClick={() => openScan(item.scanId)}>
                        Open
                      </button>
                    </td>
                  </tr>
                ))}
                {history.length === 0 && (
                  <tr>
                    <td colSpan={5}>No scan history yet.</td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
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
      </section>
    );
  };

  const renderToolManager = (): React.JSX.Element => {
    const isProfileSection = toolSection === "codebase" || toolSection === "website" || toolSection === "ip";
    const profile = (isProfileSection ? toolSection : activeToolProfile) as ToolScanProfile;
    const profileMeta = TOOL_PROFILE_META[profile];
    const profileStats = toolProfileStats[profile];

    return (
      <section className="panel stack-gap">
        <SubTabs
          tabs={[
            { key: "codebase", label: "Codebase Tools", icon: "CB" },
            { key: "website", label: "Website Tools", icon: "WS" },
            { key: "ip", label: "IP Tools", icon: "IP" },
            { key: "roles", label: "Role Drill-Down", icon: "RL" },
            { key: "provisioning", label: "Provisioning", icon: "PV" },
          ]}
          active={toolSection}
          onChange={(value) => setToolSection(value as ToolManagerSection)}
        />

        {isProfileSection && (
          <>
            <div className="subpanel">
              <div className="tool-manager-head">
                <h3>{profileMeta.label}</h3>
                <div className="tool-actions">
                  <button type="button" onClick={() => loadTools()}>
                    Refresh
                  </button>
                  <button
                    type="button"
                    onClick={() => bootstrapToolsByProfile(profile, "core", "Core profile provisioning completed.")}
                    disabled={toolBusyKey === `bootstrap-${profile}-core` || !roleCaps.canProvisionTools}
                    title={!roleCaps.canProvisionTools ? `Role ${role} cannot provision toolchains.` : ""}
                  >
                    {toolBusyKey === `bootstrap-${profile}-core` ? "Preparing..." : "Install Core Profile"}
                  </button>
                  <button
                    type="button"
                    onClick={() => bootstrapToolsByProfile(profile, "full", "Full profile provisioning completed.")}
                    disabled={toolBusyKey === `bootstrap-${profile}-full` || !roleCaps.canProvisionTools}
                    title={!roleCaps.canProvisionTools ? `Role ${role} cannot provision toolchains.` : ""}
                  >
                    {toolBusyKey === `bootstrap-${profile}-full` ? "Preparing..." : "Install Full Profile"}
                  </button>
                </div>
              </div>
              <p className="muted-text">{profileMeta.helper}</p>
              {!roleCaps.canProvisionTools && (
                <p className="muted-text">Provisioning is restricted for role {role}. Contact Admin/Security Analyst.</p>
              )}
              <div className="tool-summary-grid">
                <span>Tools in profile: {profileStats.total}</span>
                <span>Ready on host: {profileStats.ready}</span>
                <span>Integrated runners: {profileStats.integrated}</span>
                <span>Target mode now: {targetMode === "runtime-ip" ? "Runtime/URL/IP" : "Codebase"}</span>
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
                      <th>Scan Profiles</th>
                      <th>Category</th>
                      <th>Modes</th>
                      <th>Vulnerability Coverage</th>
                      <th>Integrated</th>
                      <th>Availability</th>
                      <th>Source</th>
                      <th>Command</th>
                      <th>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredToolRows.map((row) => {
                      const checkKey = `check-${row.name}`;
                      const installKey = `install-${row.name}`;
                      const runKey = `run-${row.name}`;
                      const status = row.status;
                      const profileText = row.scan_profiles.map((item) => TOOL_PROFILE_META[item].label).join(", ");
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
                          <td>{row.target_modes.join(", ")}</td>
                          <td>{row.vulnerability_classes.join(", ")}</td>
                          <td>{row.integrated ? "Yes" : "Catalog"}</td>
                          <td>{status ? (status.available ? "Ready" : "Missing") : "Unknown"}</td>
                          <td>{status?.source || row.host_source || "-"}</td>
                          <td>{status?.command || row.host_command || row.command}</td>
                          <td>
                            <div className="tool-actions">
                              <button
                                type="button"
                                onClick={() => checkTool(row.name)}
                                disabled={toolBusyKey === checkKey || !roleCaps.canManageTools || !row.integrated}
                                title={
                                  !row.integrated
                                    ? "Catalog visibility only. Direct one-click run is available for integrated tools."
                                    : !roleCaps.canManageTools
                                      ? `Role ${role} has read-only tool access.`
                                      : ""
                                }
                              >
                                {toolBusyKey === checkKey ? "Checking..." : "Check"}
                              </button>
                              <button
                                type="button"
                                onClick={() => installTool(row.name)}
                                disabled={toolBusyKey === installKey || !roleCaps.canManageTools || !row.integrated}
                                title={
                                  !row.integrated
                                    ? "Catalog visibility only. Direct one-click install is available for integrated tools."
                                    : !roleCaps.canManageTools
                                      ? `Role ${role} has read-only tool access.`
                                      : ""
                                }
                              >
                                {toolBusyKey === installKey ? "Installing..." : "Install"}
                              </button>
                              <button
                                type="button"
                                onClick={() => runSingleTool(row.name)}
                                disabled={toolBusyKey === runKey || !roleCaps.canManageTools || !row.integrated}
                                title={
                                  !row.integrated
                                    ? "Catalog visibility only. Direct one-click run is available for integrated tools."
                                    : !roleCaps.canManageTools
                                    ? `Role ${role} has read-only tool access.`
                                    : "Runs this tool only against current target field value."
                                }
                              >
                                {toolBusyKey === runKey ? "Running..." : "Run"}
                              </button>
                            </div>
                          </td>
                        </tr>
                      );
                    })}
                    {filteredToolRows.length === 0 && (
                      <tr>
                        <td colSpan={10}>No tools match this profile/search.</td>
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

        {toolSection === "provisioning" && (
          <>
            <div className="subpanel">
              <div className="tool-manager-head">
                <h3>One-Click Tool Provisioning</h3>
                <div className="tool-actions">
                  <button
                    type="button"
                    onClick={() => bootstrapToolsByProfile("all", "core", "Core enterprise toolchain is ready.")}
                    disabled={toolBusyKey === "bootstrap-all-core" || !roleCaps.canProvisionTools}
                    title={!roleCaps.canProvisionTools ? `Role ${role} cannot provision toolchains.` : ""}
                  >
                    {toolBusyKey === "bootstrap-all-core" ? "Preparing..." : "Prepare This Laptop (Core)"}
                  </button>
                  <button
                    type="button"
                    onClick={() => bootstrapToolsByProfile("all", "full", "Full catalog bootstrap completed.")}
                    disabled={toolBusyKey === "bootstrap-all-full" || !roleCaps.canProvisionTools}
                    title={!roleCaps.canProvisionTools ? `Role ${role} cannot provision toolchains.` : ""}
                  >
                    {toolBusyKey === "bootstrap-all-full" ? "Preparing..." : "Prepare Full Catalog (Best Effort)"}
                  </button>
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
                Core mode installs integrated tools that run directly in CodeSentinelX. Full mode attempts catalog tools too
                (some require vendor setup or separate licensing).
              </p>
              <div className="provision-grid">
                {TOOL_PROFILES.map((item) => (
                  <article key={item} className="provision-card">
                    <h4>{TOOL_PROFILE_META[item].label}</h4>
                    <p className="muted-text">{TOOL_PROFILE_META[item].helper}</p>
                    <p>
                      Ready: {toolProfileStats[item].ready}/{toolProfileStats[item].total}
                    </p>
                    <div className="button-row">
                      <button
                        type="button"
                        onClick={() => bootstrapToolsByProfile(item, "core", `${TOOL_PROFILE_META[item].label} core ready.`)}
                        disabled={toolBusyKey === `bootstrap-${item}-core` || !roleCaps.canProvisionTools}
                        title={!roleCaps.canProvisionTools ? `Role ${role} cannot provision toolchains.` : ""}
                      >
                        Core
                      </button>
                      <button
                        type="button"
                        onClick={() => bootstrapToolsByProfile(item, "full", `${TOOL_PROFILE_META[item].label} full bootstrap done.`)}
                        disabled={toolBusyKey === `bootstrap-${item}-full` || !roleCaps.canProvisionTools}
                        title={!roleCaps.canProvisionTools ? `Role ${role} cannot provision toolchains.` : ""}
                      >
                        Full
                      </button>
                    </div>
                  </article>
                ))}
              </div>
            </div>
          </>
        )}

        <div className="subpanel">
          <h3>Tool Action Logs</h3>
          <div className="log-console">
            {toolActionLogs.length > 0 ? (
              toolActionLogs.map((line, index) => (
                <div key={`${index}-${line}`} className="log-line">
                  {line}
                </div>
              ))
            ) : (
              <p className="muted-text">No tool actions yet.</p>
            )}
          </div>
        </div>
      </section>
    );
  };

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand panel">
          <p className="brand-eyebrow">CODESENTINEL X</p>
          <h1>Security Command</h1>
          <p>Scan every line. Quantify every risk.</p>
        </div>

        <nav className="panel nav">
          {TABS.map((item) => (
            <button
              key={item.key}
              type="button"
              className={tab === item.key ? "nav-active" : ""}
              onClick={() => setTab(item.key)}
              title={`Shortcut: Alt+${item.shortcut}`}
            >
              <span className="nav-icon">{item.icon}</span>
              <span className="nav-label">{item.label}</span>
              <kbd className="shortcut-hint">Alt+{item.shortcut}</kbd>
            </button>
          ))}
        </nav>

        <section className="panel status-panel">
          <h3>Live Scan Status</h3>
          <p className="status-headline">{isScanning ? "Scan running..." : "Scan status"}</p>
          <p className="status-summary">{statusText}</p>
          <div className="progress-track">
            <div className="progress-fill" style={{ width: `${Math.min(100, Math.max(0, progress))}%` }} />
          </div>
          <p className="status-percent">{progress.toFixed(1)}%</p>
          <div className="mini-log-list">
            {scanLogs.slice(0, 6).map((line, index) => (
              <div key={`${index}-${line}`} className="mini-log-line">
                {line}
              </div>
            ))}
            {scanLogs.length === 0 && <p className="muted-text">No events yet.</p>}
          </div>
          <p className="shortcut-guide">Navigation: Alt+1..6 for main tabs, 1..9 for section tabs.</p>
        </section>

        <section className="panel exports">
          <h3>Exports</h3>
          <div className="button-grid">
            <button type="button" onClick={() => exportReport("existing", "html")}>
              Existing HTML
            </button>
            <button type="button" onClick={() => exportReport("existing", "pdf")}>
              Existing PDF
            </button>
            <button type="button" onClick={() => exportReport("vulnerability", "html")}>
              Vulnerability HTML
            </button>
            <button type="button" onClick={() => exportReport("vulnerability", "pdf")}>
              Vulnerability PDF
            </button>
            <button type="button" onClick={() => exportReport("fixes", "html")}>
              Fixes HTML
            </button>
            <button type="button" onClick={() => exportReport("fixes", "pdf")}>
              Fixes PDF
            </button>
            <button type="button" onClick={() => exportReport("vulnerability", "json")}>
              Vulnerability JSON
            </button>
            <button type="button" onClick={() => exportReport("vulnerability", "sarif")}>
              Vulnerability SARIF
            </button>
            <button type="button" onClick={() => exportReport("vulnerability", "csv")}>
              Vulnerability CSV
            </button>
            <button type="button" onClick={() => exportReport("vulnerability", "patch")}>
              Patch Bundle
            </button>
          </div>
          <div className="button-row">
            <button type="button" onClick={() => previewReport("vulnerability")} disabled={!scan}>
              Preview Vulnerability
            </button>
            <button type="button" onClick={() => previewReport("existing")} disabled={!scan}>
              Preview Existing
            </button>
            <button type="button" onClick={() => previewReport("fixes")} disabled={!scan}>
              Preview Fixes
            </button>
            <button type="button" onClick={openLastExport} disabled={!lastExport}>
              Open Last Export
            </button>
          </div>
        </section>
      </aside>

      <main className="workspace">
        <header className="panel header">
          <div className="header-row">
            <label htmlFor="projectPath">Target Folder / IP / SSH</label>
            <input
              id="projectPath"
              value={projectPath}
              onChange={(event) => setProjectPath(event.target.value)}
              placeholder="C:\\projects\\critical-app  OR  https://10.0.0.8  OR  ssh://user@10.0.0.8/opt/app"
            />
            <button type="button" onClick={browseProject}>
              Browse
            </button>
            <button
              type="button"
              onClick={runScan}
              disabled={isScanning || !roleCaps.canRunScan}
              title={!roleCaps.canRunScan ? `Role ${role} cannot start scans.` : ""}
            >
              {isScanning ? "Scanning..." : "Run Scan"}
            </button>
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
          </div>
          <p className="target-mode">
            Mode: {targetMode === "runtime-ip" ? "Runtime/Remote Target Scan" : "Codebase Security Scan"}
          </p>
          <p className="role-hint">
            Role Drill-Down ({role}): {roleDrilldownSummary(role)}
          </p>
          <p className="role-hint">
            Access: scan={roleCaps.canRunScan ? "yes" : "no"} | review={roleCaps.canReviewFindings ? "yes" : "no"} |
            tools={roleCaps.canManageTools ? "manage" : "read-only"} | provisioning={roleCaps.canProvisionTools ? "yes" : "no"}
          </p>
          <div className="report-switch">
            <button
              type="button"
              className={tab === "vulnerabilities" ? "active" : ""}
              onClick={() => setTab("vulnerabilities")}
            >
              Vulnerability Report
            </button>
            <button
              type="button"
              className={tab === "existing" ? "active" : ""}
              onClick={() => setTab("existing")}
            >
              Existing Security Implementation Report
            </button>
            <button type="button" className={tab === "dashboard" ? "active" : ""} onClick={() => setTab("dashboard")}>
              Risk Overview
            </button>
            <button type="button" className={tab === "tools" ? "active" : ""} onClick={() => setTab("tools")}>
              Tool Manager
            </button>
          </div>
          <div className="status-row">
            <span>{statusText}</span>
            <div className="progress-wrap">
              <div className="progress-track">
                <div className="progress-fill" style={{ width: `${Math.min(100, Math.max(0, progress))}%` }} />
              </div>
              <span>{progress.toFixed(1)}%</span>
            </div>
          </div>
          {lastExport && <p className="export-path">Last export: {lastExport}</p>}
        </header>

        {(isPreviewLoading || reportPreviewHtml) && (
          <section className="panel preview-dock">
            <div className="preview-dock-head">
              <h3>
                Report Preview
                {previewReportType ? ` | ${previewReportType.toUpperCase()}` : ""}
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
                srcDoc={reportPreviewHtml}
                title="CodeSentinelX Report Preview"
                sandbox="allow-same-origin"
              />
            )}
          </section>
        )}

        {tab === "dashboard" && renderDashboard()}
        {tab === "existing" && renderExistingReport()}
        {tab === "vulnerabilities" && renderVulnerabilityReport()}
        {tab === "compliance" && renderCompliance()}
        {tab === "history" && renderHistory()}
        {tab === "tools" && renderToolManager()}
      </main>
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
