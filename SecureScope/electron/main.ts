import * as electron from "electron";
import log from "electron-log/main";
import { randomUUID } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { ExportService } from "../backend/exportService";
import { findingIdentity } from "../backend/reportAdapter";
import { PythonScannerBridge } from "../backend/pythonBridge";
import { ToolAccessAuthService } from "../backend/toolAccessAuth";
import { ToolManager } from "../backend/toolManager";
import { ExportRequest, ScanProgressPayload, ScanRecord, ScanRequest, UserRole } from "../backend/types";
import { ScanStore } from "../database/store";

const runtime = electron as Partial<typeof import("electron")>;
if (!runtime.app || !runtime.BrowserWindow || !runtime.dialog || !runtime.ipcMain) {
  console.error("CodeSentinelX failed to start because Electron is running in Node mode. Unset ELECTRON_RUN_AS_NODE.");
  process.exit(1);
}

const { app, BrowserWindow, dialog, ipcMain, Menu } = runtime as typeof import("electron");

log.initialize();

let mainWindow: import("electron").BrowserWindow | null = null;
let store: ScanStore | null = null;
let scannerBridge: PythonScannerBridge | null = null;
let exportService: ExportService | null = null;
let toolManager: ToolManager | null = null;
let toolAccessAuth: ToolAccessAuthService | null = null;
let scannerRootPath = "";
let storeFilePath = "";
let toolRunDirPath = "";
let exportDirPath = "";

function createWindow(): void {
  const preloadPath = path.join(__dirname, "preload.js");
  const windowIconPath = path.join(app.getAppPath(), "build", "icon.png");
  mainWindow = new BrowserWindow({
    width: 1560,
    height: 980,
    minWidth: 1280,
    minHeight: 760,
    backgroundColor: "#070d17",
    show: false,
    title: "CodeSentinelX",
    icon: windowIconPath,
    frame: false,
    autoHideMenuBar: true,
    titleBarStyle: "hidden",
    trafficLightPosition: { x: 12, y: 12 },
    webPreferences: {
      preload: preloadPath,
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false,
      devTools: true,
    },
  });
  mainWindow.setMenuBarVisibility(false);
  mainWindow.removeMenu();

  const devUrl = process.env.ELECTRON_START_URL;
  if (devUrl) {
    mainWindow.loadURL(devUrl).catch((error: unknown) => log.error("Failed to load renderer dev URL", error));
  } else {
    const indexPath = path.join(__dirname, "..", "..", "dist", "frontend", "index.html");
    mainWindow.loadFile(indexPath).catch((error: unknown) => log.error("Failed to load renderer bundle", error));
  }

  mainWindow.once("ready-to-show", () => mainWindow?.show());
  mainWindow.on("closed", () => {
    mainWindow = null;
  });
}

function emitProgress(payload: ScanProgressPayload): void {
  mainWindow?.webContents.send("scan:progress", payload);
}

app.whenReady().then(async () => {
  try {
    Menu.setApplicationMenu(null);
    const logicalCores = Math.max(2, Math.min(8, os.cpus().length || 4));
    const toolWorkers = Math.max(2, Math.min(6, logicalCores));
    if (!process.env.CODESENTINELX_DISABLE_APP_TOOLCHAIN) {
      process.env.CODESENTINELX_DISABLE_APP_TOOLCHAIN = "1";
    }
    if (!process.env.USS_USE_EXTERNAL_TOOLS) {
      process.env.USS_USE_EXTERNAL_TOOLS = "0";
    }
    if (!process.env.USS_AUTO_BOOTSTRAP_TOOLS) {
      process.env.USS_AUTO_BOOTSTRAP_TOOLS = "0";
    }
    if (!process.env.USS_ALLOW_HOST_INSTALLERS) {
      process.env.USS_ALLOW_HOST_INSTALLERS = "0";
    }
    if (!process.env.USS_PREFER_LOCAL_TOOLS) {
      process.env.USS_PREFER_LOCAL_TOOLS = "0";
    }
    if (!process.env.USS_ENABLE_BUILTIN_RUNTIME_COMPAT) {
      process.env.USS_ENABLE_BUILTIN_RUNTIME_COMPAT = "0";
    }
    if (!process.env.USS_STRICT_AUTHENTIC_RESULTS_ONLY) {
      process.env.USS_STRICT_AUTHENTIC_RESULTS_ONLY = "1";
    }
    if (!process.env.USS_ALLOW_EMBEDDED_COMPAT_WRAPPERS) {
      process.env.USS_ALLOW_EMBEDDED_COMPAT_WRAPPERS = "0";
    }
    if (!process.env.USS_FILE_SCAN_WORKERS) {
      process.env.USS_FILE_SCAN_WORKERS = String(logicalCores);
    }
    if (!process.env.USS_EXTERNAL_TOOL_WORKERS) {
      process.env.USS_EXTERNAL_TOOL_WORKERS = String(toolWorkers);
    }
    // Desktop runtime is configured for uncapped finding collection.
    process.env.USS_MAX_FINDINGS = "0";
    for (const key of Object.keys(process.env)) {
      if (/^USS_(?:.*_)?TOOLS$/.test(key) || key === "USS_TOOLS_DIR") {
        delete process.env[key];
      }
    }
    scannerRootPath = resolveScannerRoot(app.getAppPath());
    storeFilePath = path.join(app.getPath("userData"), "codesentinelx-store.json");
    const exportDir = path.join(app.getPath("documents"), "CodeSentinelX", "exports");
    exportDirPath = exportDir;
    toolRunDirPath = path.join(app.getPath("documents"), "CodeSentinelX", "tool-runs");

    store = await ScanStore.create(storeFilePath);
    scannerBridge = new PythonScannerBridge(scannerRootPath);
    exportService = new ExportService(exportDir);
    toolManager = new ToolManager(scannerRootPath, toolRunDirPath);
    toolAccessAuth = new ToolAccessAuthService();
    process.env.USS_AI_REMEDIATION_PROVIDER = "local";
    delete process.env.USS_AI_OLLAMA_URL;
    delete process.env.USS_AI_REMEDIATION_MODEL;
    delete process.env.USS_AI_REMEDIATION_MAX_FINDINGS;
    delete process.env.USS_AI_REMEDIATION_TIMEOUT_SECONDS;
    log.info("Desktop runtime is locked to local codebase analysis only. App-managed binaries and network scanners are disabled.");
    createWindow();

    app.on("activate", () => {
      if (BrowserWindow.getAllWindows().length === 0) {
        createWindow();
      }
    });
  } catch (error) {
    log.error("Failed to initialize CodeSentinelX runtime", error);
    app.quit();
  }
});

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") {
    app.quit();
  }
});

function requireToolManagerAccess(authToken: string | undefined | null): void {
  if (!toolAccessAuth) {
    throw new Error("Tool Manager access service is not initialized.");
  }
  toolAccessAuth.assertAuthorized(authToken || "");
}

function resolveAuthToken(payload: unknown): string {
  if (!payload || typeof payload !== "object") {
    return "";
  }
  const raw = (payload as { authToken?: unknown }).authToken;
  if (typeof raw !== "string") {
    return "";
  }
  return raw.trim();
}

ipcMain.handle("dialog:pickFolder", async () => {
  const result = await dialog.showOpenDialog({
    title: "Select project folder to scan",
    properties: ["openDirectory"],
  });
  return result.canceled ? null : result.filePaths[0] || null;
});

ipcMain.handle("window:minimize", () => {
  mainWindow?.minimize();
});

ipcMain.handle("window:toggleMaximize", () => {
  if (!mainWindow) {
    return false;
  }
  if (mainWindow.isMaximized()) {
    mainWindow.unmaximize();
    return false;
  }
  mainWindow.maximize();
  return true;
});

ipcMain.handle("window:close", () => {
  mainWindow?.close();
});

ipcMain.handle("scan:start", async (_event, request: ScanRequest) => {
  if (!scannerBridge || !store) {
    throw new Error("CodeSentinelX backend is not initialized.");
  }

  const scanId = randomUUID();
  const normalizedRequest: ScanRequest = {
    projectPath: request.projectPath,
    requestedBy: request.requestedBy || "local-user",
    role: request.role || "Security Analyst",
    scanPreset: request.scanPreset || "standard",
    scmContext: request.scmContext || undefined,
  };

  await store.addAudit({
    scanId,
    action: "scan.started",
    actor: normalizedRequest.requestedBy || "local-user",
    role: normalizedRequest.role || "Security Analyst",
    details: `Started scan for ${normalizedRequest.projectPath}`,
  });

  emitProgress({
    scanId,
    stage: "queued",
    progress: 0,
    message: "Scan queued",
    status: "running",
  });

  try {
    const result = await scannerBridge.runScan(scanId, normalizedRequest, emitProgress);
    const record: ScanRecord = {
      scanId,
      projectPath: normalizedRequest.projectPath,
      requestedBy: normalizedRequest.requestedBy || "local-user",
      role: normalizedRequest.role || "Security Analyst",
      startedAt: result.startedAt,
      completedAt: result.completedAt,
      report: result.report,
      findingStates: {},
    };
    await store.addScan(record);
    await store.addAudit({
      scanId,
      action: "scan.completed",
      actor: record.requestedBy,
      role: record.role,
      details: `Codebase scan completed with ${record.report.vulnerability_fixed_code_report.summary.total_findings} findings`,
    });

    const view = store.getScanView(scanId);
    if (!view) {
      throw new Error("Unable to load completed scan result.");
    }
    return view;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (isStoppedScanMessage(message)) {
      await store.addAudit({
        scanId,
        action: "scan.stopped",
        actor: normalizedRequest.requestedBy || "local-user",
        role: normalizedRequest.role || "Security Analyst",
        details: "Scan stopped by user.",
      });
      throw new Error("Scan stopped by user.");
    }

    emitProgress({
      scanId,
      stage: "failed",
      progress: 100,
      message,
      status: "failed",
    });
    await store.addAudit({
      scanId,
      action: "scan.failed",
      actor: normalizedRequest.requestedBy || "local-user",
      role: normalizedRequest.role || "Security Analyst",
      details: message,
    });
    throw error;
  }
});

ipcMain.handle("scan:pause", async (_event, scanId: string) => {
  if (!scannerBridge) {
    throw new Error("Scanner bridge is not initialized.");
  }
  const result = await scannerBridge.pauseScan(scanId);
  if (result.success) {
    await store?.addAudit({
      scanId,
      action: "scan.paused",
      actor: "local-user",
      role: "Security Analyst",
      details: "Scan paused by user.",
    });
  }
  return result;
});

ipcMain.handle("scan:resume", async (_event, scanId: string) => {
  if (!scannerBridge) {
    throw new Error("Scanner bridge is not initialized.");
  }
  const result = await scannerBridge.resumeScan(scanId);
  if (result.success) {
    await store?.addAudit({
      scanId,
      action: "scan.resumed",
      actor: "local-user",
      role: "Security Analyst",
      details: "Scan resumed by user.",
    });
  }
  return result;
});

ipcMain.handle("scan:stop", async (_event, scanId: string) => {
  if (!scannerBridge) {
    throw new Error("Scanner bridge is not initialized.");
  }
  const result = await scannerBridge.stopScan(scanId);
  if (result.success) {
    await store?.addAudit({
      scanId,
      action: "scan.stop_requested",
      actor: "local-user",
      role: "Security Analyst",
      details: "Scan stop requested by user.",
    });
  }
  return result;
});

ipcMain.handle("scan:history", () => {
  return store?.listHistory() || [];
});

ipcMain.handle("help:getGuide", async () => {
  if (!exportService || !scannerRootPath) {
    return { markdown: "", markdownPath: "", pdfPath: "" };
  }
  const { markdown, markdownPath } = await exportService.getUserGuideMarkdown(scannerRootPath);
  const pdfPath = await exportService.ensureUserGuidePdf(scannerRootPath);
  return { markdown, markdownPath, pdfPath };
});

ipcMain.handle("help:ensurePdf", async () => {
  if (!exportService || !scannerRootPath) {
    throw new Error("Help guide service is unavailable.");
  }
  return exportService.ensureUserGuidePdf(scannerRootPath);
});

ipcMain.handle("report:history", async () => {
  if (!exportDirPath) {
    return [];
  }
  const entries = await fs.promises.readdir(exportDirPath, { withFileTypes: true }).catch(() => []);
  const reports = entries
    .filter((entry) => entry.isFile())
    .map((entry) => {
      const fileName = entry.name;
      const fullPath = path.join(exportDirPath, fileName);
      const parsed = /^(\d{4}-\d{2}-\d{2})_(\d{2}-\d{2}-\d{2}(?:-\d{3})?)_([A-Za-z0-9._-]+)_(.+)\.(html|pdf|json|xml|csv|patch|sairf)$/i.exec(
        fileName,
      );
      let generatedAt = "";
      let reportType = "unknown";
      let target = "";
      let format = path.extname(fileName).replace(/^\./, "").toLowerCase();
      if (parsed) {
        const [, datePart, timePart, typePart, targetPart, ext] = parsed;
        const normalizedTime = timePart.replace(/-/g, ":").replace(/:(\d{3})$/, ".$1");
        generatedAt = `${datePart}T${normalizedTime}`;
        reportType = typePart.toLowerCase();
        target = targetPart.replace(/-/g, " ");
        format = ext.toLowerCase();
      }
      const roleScope =
        reportType.startsWith("fixes")
          ? "Developer"
          : reportType.startsWith("existing")
            ? "Auditor"
            : reportType.startsWith("vulnerability")
              ? "Security Analyst"
              : reportType.startsWith("combined")
                ? "Admin / Management"
                : "Unknown";
      return {
        fileName,
        fullPath,
        generatedAt,
        reportType,
        target,
        format,
        roleScope,
      };
    })
    .sort((a, b) => {
      const left = Date.parse(a.generatedAt || "");
      const right = Date.parse(b.generatedAt || "");
      if (Number.isFinite(left) && Number.isFinite(right)) {
        return right - left;
      }
      return b.fileName.localeCompare(a.fileName);
    });
  return reports;
});

ipcMain.handle("report:delete", async (_event, payload?: { paths?: string[]; all?: boolean }) => {
  if (!exportDirPath) {
    return { deleted: 0, failed: 0 };
  }
  const requestedAll = Boolean(payload?.all);
  const requestedPaths = Array.isArray(payload?.paths) ? payload?.paths.filter((item): item is string => typeof item === "string" && item.trim().length > 0) : [];
  const targets = new Set<string>();
  if (requestedAll) {
    const entries = await fs.promises.readdir(exportDirPath, { withFileTypes: true }).catch(() => []);
    for (const entry of entries) {
      if (!entry.isFile()) {
        continue;
      }
      targets.add(path.join(exportDirPath, entry.name));
    }
  } else {
    for (const item of requestedPaths) {
      const resolved = path.resolve(item);
      const exportRoot = path.resolve(exportDirPath);
      if (resolved.startsWith(exportRoot + path.sep) || resolved === exportRoot) {
        targets.add(resolved);
      }
    }
  }
  let deleted = 0;
  let failed = 0;
  for (const target of targets) {
    try {
      const stat = await fs.promises.stat(target).catch(() => null);
      if (!stat || !stat.isFile()) {
        continue;
      }
      await fs.promises.unlink(target);
      deleted += 1;
    } catch {
      failed += 1;
    }
  }
  await store?.addAudit({
    action: "report.history.cleaned",
    actor: "local-user",
    role: "Admin",
    details: `Report cleanup executed: deleted=${deleted}, failed=${failed}, mode=${requestedAll ? "all" : "selected"}`,
  });
  return { deleted, failed };
});

ipcMain.handle("scan:portfolioSummary", () => {
  return store?.getPortfolioSummary() || {
    scansTotal: 0,
    repositoriesTotal: 0,
    trendDirection: "unavailable",
    trendDelta: 0,
    hotModules: [],
    recurringCwe: [],
    fixVelocityPercent: 0,
    suppressionDriftScore: 0,
  };
});

ipcMain.handle("scan:getById", (_event, scanId: string) => {
  return store?.getScanView(scanId) || null;
});

ipcMain.handle("scan:markReviewed", async (_event, payload: { scanId: string; findingId: string; actor: string; role: UserRole }) => {
  if (!store) {
    return null;
  }
  const updated = await store.markReviewed(payload.scanId, payload.findingId, payload.actor);
  if (updated) {
    await store.addAudit({
      scanId: payload.scanId,
      action: "finding.reviewed",
      actor: payload.actor,
      role: payload.role,
      details: `Marked finding ${payload.findingId} as reviewed`,
    });
  }
  return updated;
});

ipcMain.handle("scan:generatePatch", (_event, payload: { scanId: string; findingId: string }) => {
  if (!store) {
    return null;
  }
  const scan = store.getScanView(payload.scanId);
  if (!scan) {
    return null;
  }
  const finding = scan.report.vulnerability_fixed_code_report.findings.find((item) => findingIdentity(item) === payload.findingId);
  return finding?.patch_preview || null;
});

ipcMain.handle("scan:export", async (_event, request: ExportRequest) => {
  if (!store || !exportService) {
    throw new Error("Export service is unavailable.");
  }
  const scan = store.getScanView(request.scanId);
  if (!scan) {
    throw new Error(`Scan ${request.scanId} not found.`);
  }
  let outputPath = "";
  if (request.format === "pdf") {
    const html = exportService.renderReportHtml(scan, request.reportType, request.reportStyle, request.role);
    const destination = exportService.resolveOutputPath(scan, request.reportType, request.format, request.reportStyle);
    try {
      await renderHtmlAsPdf(html, destination);
      outputPath = destination;
    } catch (error) {
      log.warn("HTML PDF rendering failed. Falling back to text PDF exporter.", error);
      outputPath = await exportService.exportReport(scan, request);
    }
  } else {
    outputPath = await exportService.exportReport(scan, request);
  }
  await store.addAudit({
    scanId: request.scanId,
    action: "report.exported",
    actor: "local-user",
    role: (request.role || scan.report.executive_summary.scan_role || "Security Analyst") as UserRole,
    details: `Exported ${request.reportType} report in ${request.format} format -> ${outputPath}`,
  });
  return outputPath;
});

ipcMain.handle(
  "scan:renderHtml",
  (
    _event,
    payload: { scanId: string; reportType: ExportRequest["reportType"]; reportStyle?: ExportRequest["reportStyle"]; role?: ExportRequest["role"] },
  ) => {
    if (!store || !exportService) {
      throw new Error("Report renderer is unavailable.");
    }
    const scan = store.getScanView(payload.scanId);
    if (!scan) {
      throw new Error(`Scan ${payload.scanId} not found.`);
    }
    return exportService.renderReportHtml(scan, payload.reportType, payload.reportStyle, payload.role);
  },
);

ipcMain.handle("shell:openPath", async (_event, targetPath: string) => {
  if (!targetPath) {
    return "No path provided.";
  }
  return electron.shell.openPath(targetPath);
});

ipcMain.handle("audit:list", (_event, scanId?: string) => {
  return store?.listAudits(scanId) || [];
});

ipcMain.handle("tools:authConfig", async (_event, payload?: { authToken?: string }) => {
  if (!toolAccessAuth) {
    return {
      enabled: false,
      allowedEmailMasked: "",
      authMode: "totp_only",
      otpRequired: false,
      otpTtlSeconds: 300,
      sessionTtlSeconds: 3600,
      mfaRequired: false,
      mfaIssuer: "CodeSentinelX",
      smtpConfigured: false,
      sessionValid: false,
      message: "Tool Manager access service is not initialized.",
    };
  }
  return toolAccessAuth.getConfig(resolveAuthToken(payload));
});

ipcMain.handle("tools:requestOtp", async (_event, payload: { email: string }) => {
  if (!toolAccessAuth) {
    throw new Error("Tool Manager access service is not initialized.");
  }
  const result = await toolAccessAuth.requestOtp(String(payload?.email || ""));
  await store?.addAudit({
    action: "tool.auth.otp_requested",
    actor: "local-user",
    role: "Admin",
    details: result.success ? `OTP issued for ${result.message}` : `OTP request denied (${result.message})`,
  });
  return result;
});

ipcMain.handle("tools:verifyAccess", async (_event, payload: { email: string; otp: string; mfaCode?: string }) => {
  if (!toolAccessAuth) {
    throw new Error("Tool Manager access service is not initialized.");
  }
  const result = toolAccessAuth.verifyAccess(String(payload?.email || ""), String(payload?.otp || ""), String(payload?.mfaCode || ""));
  await store?.addAudit({
    action: "tool.auth.verified",
    actor: "local-user",
    role: "Admin",
    details: result.success ? `Tool Manager access granted (${result.email || "owner"})` : `Tool Manager access denied (${result.message})`,
  });
  return result;
});

ipcMain.handle("tools:logout", async (_event, payload: { authToken?: string }) => {
  if (!toolAccessAuth) {
    throw new Error("Tool Manager access service is not initialized.");
  }
  const result = toolAccessAuth.revokeSession(resolveAuthToken(payload));
  await store?.addAudit({
    action: "tool.auth.logout",
    actor: "local-user",
    role: "Admin",
    details: result.message,
  });
  return result;
});

ipcMain.handle("tools:list", async (_event, payload?: { authToken?: string }) => {
  if (!toolManager) {
    throw new Error("Tool manager is not initialized.");
  }
  requireToolManagerAccess(resolveAuthToken(payload));
  return toolManager.listTools();
});

ipcMain.handle("app:resetLocalStateCache", async (_event, payload?: { authToken?: string }) => {
  requireToolManagerAccess(resolveAuthToken(payload));
  if (!scannerRootPath || !storeFilePath || !toolRunDirPath) {
    throw new Error("CodeSentinelX paths are not initialized.");
  }

  const storeBackupPath = `${storeFilePath}.reset-${new Date().toISOString().replaceAll(":", "-").replaceAll(".", "-")}.bak`;
  if (fs.existsSync(storeFilePath)) {
    await fs.promises.rename(storeFilePath, storeBackupPath).catch(() => undefined);
  }
  await fs.promises.unlink(`${storeFilePath}.tmp`).catch(() => undefined);

  await fs.promises.rm(toolRunDirPath, { recursive: true, force: true });
  await fs.promises.mkdir(toolRunDirPath, { recursive: true });

  store = await ScanStore.create(storeFilePath);
  scannerBridge = new PythonScannerBridge(scannerRootPath);
  toolManager = new ToolManager(scannerRootPath, toolRunDirPath);

  await store.addAudit({
    action: "app.reset.local_state_cache",
    actor: "local-user",
    role: "Admin",
    details: "Local state and cache reset via Tool Manager.",
  });
  log.info("Reset completed. App-managed external toolchain remains disabled.");

  return {
    success: true,
    message: "Local state and cache reset completed.",
    storeBackupPath: fs.existsSync(storeBackupPath) ? storeBackupPath : "",
    toolchainCachePath: "",
    seedMessage: "App-managed external toolchain is disabled by security policy.",
  };
});

async function renderHtmlAsPdf(html: string, outputPath: string): Promise<void> {
  const tempHtmlPath = path.join(app.getPath("temp"), `codesentinelx-report-${randomUUID()}.html`);
  await fs.promises.writeFile(tempHtmlPath, html, "utf-8");

  const printWindow = new BrowserWindow({
    show: false,
    width: 1600,
    height: 1100,
    backgroundColor: "#ffffff",
    webPreferences: {
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      devTools: false,
    },
  });

  try {
    await printWindow.loadFile(tempHtmlPath);
    await printWindow.webContents.executeJavaScript(
      "new Promise((resolve) => requestAnimationFrame(() => setTimeout(resolve, 350)))",
      true,
    );
    const pdf = await printWindow.webContents.printToPDF({
      printBackground: true,
      pageSize: "A4",
      margins: {
        top: 0.4,
        bottom: 0.4,
        left: 0.35,
        right: 0.35,
      },
      preferCSSPageSize: true,
    });
    await fs.promises.writeFile(outputPath, pdf);
  } finally {
    await fs.promises.unlink(tempHtmlPath).catch(() => undefined);
    if (!printWindow.isDestroyed()) {
      printWindow.destroy();
    }
  }
}

function resolveScannerRoot(appPath: string): string {
  const envRoot = process.env.CODESENTINELX_SCANNER_ROOT;
  const candidates = [
    envRoot,
    path.resolve(appPath, ".."),
    appPath,
    path.resolve(process.cwd(), ".."),
    process.cwd(),
  ].filter(Boolean) as string[];

  for (const candidate of candidates) {
    const cliPath = path.join(candidate, "universal_security_scanner", "cli.py");
    const pyproject = path.join(candidate, "pyproject.toml");
    if (fs.existsSync(cliPath) && fs.existsSync(pyproject)) {
      return candidate;
    }
  }
  return process.cwd();
}

function isStoppedScanMessage(message: string): boolean {
  const normalized = message.trim().toLowerCase();
  return normalized.includes("scan stopped by user");
}

