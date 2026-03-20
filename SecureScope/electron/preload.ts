import { contextBridge, ipcRenderer } from "electron";

import { ExportRequest, ScanRequest, UserRole } from "../backend/types";

const api = {
  minimizeWindow: async (): Promise<void> => ipcRenderer.invoke("window:minimize"),
  toggleMaximizeWindow: async (): Promise<boolean> => ipcRenderer.invoke("window:toggleMaximize"),
  closeWindow: async (): Promise<void> => ipcRenderer.invoke("window:close"),
  pickProjectFolder: async (): Promise<string | null> => ipcRenderer.invoke("dialog:pickFolder"),
  startScan: async (request: ScanRequest) => ipcRenderer.invoke("scan:start", request),
  pauseScan: async (scanId: string) => ipcRenderer.invoke("scan:pause", scanId),
  resumeScan: async (scanId: string) => ipcRenderer.invoke("scan:resume", scanId),
  stopScan: async (scanId: string) => ipcRenderer.invoke("scan:stop", scanId),
  getScanHistory: async () => ipcRenderer.invoke("scan:history"),
  getPortfolioSummary: async () => ipcRenderer.invoke("scan:portfolioSummary"),
  getScanById: async (scanId: string) => ipcRenderer.invoke("scan:getById", scanId),
  markReviewed: async (payload: { scanId: string; findingId: string; actor: string; role: UserRole }) =>
    ipcRenderer.invoke("scan:markReviewed", payload),
  generatePatch: async (payload: { scanId: string; findingId: string }) => ipcRenderer.invoke("scan:generatePatch", payload),
  exportReport: async (request: ExportRequest) => ipcRenderer.invoke("scan:export", request),
  renderReportHtml: async (payload: { scanId: string; reportType: ExportRequest["reportType"]; reportStyle?: ExportRequest["reportStyle"] }) =>
    ipcRenderer.invoke("scan:renderHtml", payload),
  openPath: async (targetPath: string) => ipcRenderer.invoke("shell:openPath", targetPath),
  listAuditLogs: async (scanId?: string) => ipcRenderer.invoke("audit:list", scanId),
  getToolAccessConfig: async (payload?: { authToken?: string }) => ipcRenderer.invoke("tools:authConfig", payload),
  requestToolAccessOtp: async (payload: { email: string }) => ipcRenderer.invoke("tools:requestOtp", payload),
  verifyToolAccess: async (payload: { email: string; otp: string; mfaCode?: string }) =>
    ipcRenderer.invoke("tools:verifyAccess", payload),
  logoutToolAccess: async (payload: { authToken?: string }) => ipcRenderer.invoke("tools:logout", payload),
  listTools: async (payload?: { authToken?: string }) => ipcRenderer.invoke("tools:list", payload),
  resetLocalStateCache: async (payload?: { authToken?: string }) => ipcRenderer.invoke("app:resetLocalStateCache", payload),
  onScanProgress: (
    callback: (payload: {
      scanId: string;
      stage: string;
      progress: number;
      message: string;
      currentFile?: string;
      status: "running" | "paused" | "completed" | "failed" | "stopped";
    }) => void,
  ) => {
    const listener = (
      _event: Electron.IpcRendererEvent,
      payload: {
        scanId: string;
        stage: string;
        progress: number;
        message: string;
        currentFile?: string;
        status: "running" | "paused" | "completed" | "failed" | "stopped";
      },
    ) => callback(payload);

    ipcRenderer.on("scan:progress", listener);
    return () => {
      ipcRenderer.removeListener("scan:progress", listener);
    };
  },
};

contextBridge.exposeInMainWorld("codeSentinelX", api);
