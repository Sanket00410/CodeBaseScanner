import {
  AuditLogEntry,
  ManagementReportContext,
  PortfolioSummary,
  ReportHistoryItem,
  ScmDiffContext,
  ScanHistoryItem,
  ScanProgress,
  ScanView,
  ToolCatalogItem,
  ResetLocalStateCacheResult,
  ScanControlActionResult,
  ToolManagerAuthConfig,
  ToolManagerOtpResult,
  ToolManagerVerifyResult,
  ScanPreset,
  UserRole,
} from "./types";

declare global {
  interface Window {
    codeSentinelX: {
      minimizeWindow: () => Promise<void>;
      toggleMaximizeWindow: () => Promise<boolean>;
      closeWindow: () => Promise<void>;
      pickProjectFolder: () => Promise<string | null>;
      createThreatModel: (request: {
        projectPath: string;
        requestedBy?: string;
        framework?: "STRIDE";
      }) => Promise<import("./types").ThreatModelResult>;
      startScan: (request: {
        projectPath: string;
        requestedBy?: string;
        role?: UserRole;
        scanPreset?: ScanPreset;
        scmContext?: ScmDiffContext;
      }) => Promise<ScanView>;
      pauseScan: (scanId: string) => Promise<ScanControlActionResult>;
      resumeScan: (scanId: string) => Promise<ScanControlActionResult>;
      stopScan: (scanId: string) => Promise<ScanControlActionResult>;
      getScanHistory: () => Promise<ScanHistoryItem[]>;
      getHelpGuide: () => Promise<{ markdown: string; markdownPath: string; htmlPath: string; pdfPath: string }>;
      ensureHelpHtml: () => Promise<string>;
      ensureHelpPdf: () => Promise<string>;
      getReportHistory: () => Promise<ReportHistoryItem[]>;
      deleteReportHistory: (payload?: { paths?: string[]; all?: boolean }) => Promise<{ deleted: number; failed: number }>;
      getPortfolioSummary: () => Promise<PortfolioSummary>;
      getScanById: (scanId: string, role?: UserRole) => Promise<ScanView | null>;
      markReviewed: (payload: { scanId: string; findingId: string; actor: string; role: UserRole }) => Promise<ScanView | null>;
      generatePatch: (payload: { scanId: string; findingId: string }) => Promise<string | null>;
      exportReport: (request: {
        scanId: string;
        role?: UserRole;
        reportType: "existing" | "vulnerability" | "fixes" | "finding_details" | "combined" | "management";
        format: "json" | "xml" | "html" | "pdf" | "sarif" | "csv" | "patch";
        reportStyle?: "classic" | "modern";
        managementContext?: ManagementReportContext;
      }) => Promise<string>;
      renderReportHtml: (payload: {
        scanId: string;
        role?: UserRole;
        reportType: "existing" | "vulnerability" | "fixes" | "finding_details" | "combined" | "management";
        reportStyle?: "classic" | "modern";
        managementContext?: ManagementReportContext;
      }) => Promise<string>;
      openPath: (targetPath: string) => Promise<string>;
      listAuditLogs: (scanId?: string) => Promise<AuditLogEntry[]>;
      getToolAccessConfig: (payload?: { authToken?: string }) => Promise<ToolManagerAuthConfig>;
      requestToolAccessOtp: (payload: { email: string }) => Promise<ToolManagerOtpResult>;
      verifyToolAccess: (payload: { email: string; otp: string; mfaCode?: string }) => Promise<ToolManagerVerifyResult>;
      logoutToolAccess: (payload: { authToken?: string }) => Promise<{ success: boolean; message: string }>;
      listTools: (payload?: { authToken?: string }) => Promise<ToolCatalogItem[]>;
      resetLocalStateCache: (payload?: { authToken?: string }) => Promise<ResetLocalStateCacheResult>;
      onScanProgress: (callback: (progress: ScanProgress) => void) => () => void;
    };
  }
}

export {};
