import { contextBridge, ipcRenderer } from "electron";

import { ExportRequest, ScanRequest, UserRole } from "../backend/types";

const api = {
  pickProjectFolder: async (): Promise<string | null> => ipcRenderer.invoke("dialog:pickFolder"),
  startScan: async (request: ScanRequest) => ipcRenderer.invoke("scan:start", request),
  getScanHistory: async () => ipcRenderer.invoke("scan:history"),
  getScanById: async (scanId: string) => ipcRenderer.invoke("scan:getById", scanId),
  markReviewed: async (payload: { scanId: string; findingId: string; actor: string; role: UserRole }) =>
    ipcRenderer.invoke("scan:markReviewed", payload),
  generatePatch: async (payload: { scanId: string; findingId: string }) => ipcRenderer.invoke("scan:generatePatch", payload),
  exportReport: async (request: ExportRequest) => ipcRenderer.invoke("scan:export", request),
  renderReportHtml: async (payload: { scanId: string; reportType: ExportRequest["reportType"] }) =>
    ipcRenderer.invoke("scan:renderHtml", payload),
  openPath: async (targetPath: string) => ipcRenderer.invoke("shell:openPath", targetPath),
  listAuditLogs: async (scanId?: string) => ipcRenderer.invoke("audit:list", scanId),
  listTools: async () => ipcRenderer.invoke("tools:list"),
  checkTool: async (payload: { tool: string }) => ipcRenderer.invoke("tools:check", payload),
  installTool: async (payload: { tool: string }) => ipcRenderer.invoke("tools:install", payload),
  bootstrapTools: async (payload: { profile: "codebase" | "website" | "ip" | "all"; mode: "core" | "full" }) =>
    ipcRenderer.invoke("tools:bootstrap", payload),
  runTool: async (payload: { tool: string; target: string }) => ipcRenderer.invoke("tools:run", payload),
  resetLocalStateCache: async () => ipcRenderer.invoke("app:resetLocalStateCache"),
  onScanProgress: (
    callback: (payload: {
      scanId: string;
      stage: string;
      progress: number;
      message: string;
      currentFile?: string;
      status: "running" | "completed" | "failed";
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
        status: "running" | "completed" | "failed";
      },
    ) => callback(payload);

    ipcRenderer.on("scan:progress", listener);
    return () => {
      ipcRenderer.removeListener("scan:progress", listener);
    };
  },
};

contextBridge.exposeInMainWorld("codeSentinelX", api);
