import {
  AuditLogEntry,
  ScanHistoryItem,
  ScanProgress,
  ScanView,
  ToolActionResult,
  ToolBootstrapResult,
  ToolCatalogItem,
  ToolBootstrapMode,
  ResetLocalStateCacheResult,
  ToolScanProfile,
  UserRole,
} from "./types";

declare global {
  interface Window {
    codeSentinelX: {
      pickProjectFolder: () => Promise<string | null>;
      startScan: (request: { projectPath: string; requestedBy?: string; role?: UserRole }) => Promise<ScanView>;
      getScanHistory: () => Promise<ScanHistoryItem[]>;
      getScanById: (scanId: string) => Promise<ScanView | null>;
      markReviewed: (payload: { scanId: string; findingId: string; actor: string; role: UserRole }) => Promise<ScanView | null>;
      generatePatch: (payload: { scanId: string; findingId: string }) => Promise<string | null>;
      exportReport: (request: {
        scanId: string;
        reportType: "existing" | "vulnerability" | "fixes" | "combined";
        format: "json" | "html" | "pdf" | "sarif" | "csv" | "patch";
      }) => Promise<string>;
      renderReportHtml: (payload: { scanId: string; reportType: "existing" | "vulnerability" | "fixes" | "combined" }) => Promise<string>;
      openPath: (targetPath: string) => Promise<string>;
      listAuditLogs: (scanId?: string) => Promise<AuditLogEntry[]>;
      listTools: () => Promise<ToolCatalogItem[]>;
      checkTool: (payload: { tool: string }) => Promise<ToolActionResult>;
      installTool: (payload: { tool: string }) => Promise<ToolActionResult>;
      bootstrapTools: (payload: { profile: ToolScanProfile | "all"; mode: ToolBootstrapMode }) => Promise<ToolBootstrapResult>;
      runTool: (payload: { tool: string; target: string }) => Promise<ToolActionResult>;
      resetLocalStateCache: () => Promise<ResetLocalStateCacheResult>;
      onScanProgress: (callback: (progress: ScanProgress) => void) => () => void;
    };
  }
}

export {};
