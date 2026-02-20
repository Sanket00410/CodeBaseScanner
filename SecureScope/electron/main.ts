import * as electron from "electron";
import log from "electron-log/main";
import { randomUUID } from "node:crypto";
import fs from "node:fs";
import path from "node:path";

import { ExportService } from "../backend/exportService";
import { findingIdentity } from "../backend/reportAdapter";
import { PythonScannerBridge } from "../backend/pythonBridge";
import { ToolManager } from "../backend/toolManager";
import { ExportRequest, ScanProgressPayload, ScanRecord, ScanRequest, UserRole } from "../backend/types";
import { ScanStore } from "../database/store";

const runtime = electron as Partial<typeof import("electron")>;
if (!runtime.app || !runtime.BrowserWindow || !runtime.dialog || !runtime.ipcMain) {
  console.error("CodeSentinelX failed to start because Electron is running in Node mode. Unset ELECTRON_RUN_AS_NODE.");
  process.exit(1);
}

const { app, BrowserWindow, dialog, ipcMain } = runtime as typeof import("electron");

log.initialize();

let mainWindow: import("electron").BrowserWindow | null = null;
let store: ScanStore | null = null;
let scannerBridge: PythonScannerBridge | null = null;
let exportService: ExportService | null = null;
let toolManager: ToolManager | null = null;
let scannerRootPath = "";
let storeFilePath = "";
let toolchainCachePath = "";
let toolRunDirPath = "";
const DEFAULT_CODEBASE_TOOLS = [
  "bandit",
  "brakeman",
  "checkov",
  "clair",
  "codeql",
  "cppcheck",
  "eslint-security",
  "findsecbugs",
  "flawfinder",
  "gitleaks",
  "gosec",
  "govulncheck",
  "grype",
  "hadolint",
  "infer",
  "npm-audit",
  "osv-scanner",
  "owasp-dependency-check",
  "pip-audit",
  "safety",
  "semgrep",
  "snyk",
  "sonarqube",
  "spotbugs",
  "tfsec",
  "trivy",
].join(",");
const DEFAULT_RUNTIME_TOOLS = [
  "runtime_http_probe",
  "amass",
  "ffuf",
  "kube-bench",
  "kube-hunter",
  "nikto",
  "nmap",
  "nuclei",
  "sqlmap",
  "wapiti",
  "zap-baseline",
].join(",");

function mergeToolCsv(existingCsv: string | undefined, requiredCsv: string): string {
  const merged: string[] = [];
  const seen = new Set<string>();
  const append = (raw: string): void => {
    const value = raw.trim().toLowerCase();
    if (!value || seen.has(value)) {
      return;
    }
    seen.add(value);
    merged.push(value);
  };

  for (const item of (existingCsv || "").split(",")) {
    append(item);
  }
  for (const item of requiredCsv.split(",")) {
    append(item);
  }
  return merged.join(",");
}

function createWindow(): void {
  const preloadPath = path.join(__dirname, "preload.js");
  mainWindow = new BrowserWindow({
    width: 1560,
    height: 980,
    minWidth: 1280,
    minHeight: 760,
    backgroundColor: "#070d17",
    show: false,
    title: "CodeSentinelX",
    webPreferences: {
      preload: preloadPath,
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false,
      devTools: true,
    },
  });

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
    if (!process.env.USS_USE_EXTERNAL_TOOLS) {
      process.env.USS_USE_EXTERNAL_TOOLS = "1";
    }
    if (!process.env.USS_AUTO_BOOTSTRAP_TOOLS) {
      process.env.USS_AUTO_BOOTSTRAP_TOOLS = "1";
    }
    if (!process.env.USS_ALLOW_HOST_INSTALLERS) {
      process.env.USS_ALLOW_HOST_INSTALLERS = "0";
    }
    if (!process.env.USS_PREFER_LOCAL_TOOLS) {
      process.env.USS_PREFER_LOCAL_TOOLS = "1";
    }
    // Desktop runtime is configured for uncapped finding collection.
    process.env.USS_MAX_FINDINGS = "0";
    process.env.USS_CODEBASE_TOOLS = mergeToolCsv(process.env.USS_CODEBASE_TOOLS, DEFAULT_CODEBASE_TOOLS);
    process.env.USS_RUNTIME_TOOLS = mergeToolCsv(process.env.USS_RUNTIME_TOOLS, DEFAULT_RUNTIME_TOOLS);
    scannerRootPath = resolveScannerRoot(app.getAppPath());
    storeFilePath = path.join(app.getPath("userData"), "codesentinelx-store.json");
    const exportDir = path.join(app.getPath("documents"), "CodeSentinelX", "exports");
    toolRunDirPath = path.join(app.getPath("documents"), "CodeSentinelX", "tool-runs");
    const legacyUserDataToolchainPath = path.join(app.getPath("userData"), ".toolchain");
    toolchainCachePath = resolveToolchainPath(scannerRootPath);

    process.env.USS_TOOLS_DIR = toolchainCachePath;
    const seedStatus = await seedToolchainCache(scannerRootPath, toolchainCachePath, [legacyUserDataToolchainPath]);
    log.info(seedStatus);

    store = await ScanStore.create(storeFilePath);
    scannerBridge = new PythonScannerBridge(scannerRootPath);
    exportService = new ExportService(exportDir);
    toolManager = new ToolManager(scannerRootPath, toolRunDirPath);
    void toolManager
      .bootstrapProfile("all", "core")
      .then((result) => {
        log.info(
          `Core toolchain warmup: ready=${result.ready}/${result.total}, missing=${result.missing}, success=${result.success}`,
        );
      })
      .catch((error: unknown) => {
        log.warn("Core toolchain warmup failed", error);
      });
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

ipcMain.handle("dialog:pickFolder", async () => {
  const result = await dialog.showOpenDialog({
    title: "Select project folder to scan",
    properties: ["openDirectory"],
  });
  return result.canceled ? null : result.filePaths[0] || null;
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
    runtimeAuth: request.runtimeAuth
      ? {
          token: String(request.runtimeAuth.token || "").trim(),
          cookie: String(request.runtimeAuth.cookie || "").trim(),
          headerName: String(request.runtimeAuth.headerName || "").trim(),
          headerValue: String(request.runtimeAuth.headerValue || "").trim(),
        }
      : undefined,
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
    const targetKind = inferTargetKind(normalizedRequest.projectPath);
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
      details: `${targetKind} completed with ${record.report.vulnerability_fixed_code_report.summary.total_findings} findings`,
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
    const html = exportService.renderReportHtml(scan, request.reportType);
    const destination = exportService.resolveOutputPath(scan, request.reportType, request.format);
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
    role: "Auditor",
    details: `Exported ${request.reportType} report in ${request.format} format`,
  });
  return outputPath;
});

ipcMain.handle("scan:renderHtml", (_event, payload: { scanId: string; reportType: ExportRequest["reportType"] }) => {
  if (!store || !exportService) {
    throw new Error("Report renderer is unavailable.");
  }
  const scan = store.getScanView(payload.scanId);
  if (!scan) {
    throw new Error(`Scan ${payload.scanId} not found.`);
  }
  return exportService.renderReportHtml(scan, payload.reportType);
});

ipcMain.handle("shell:openPath", async (_event, targetPath: string) => {
  if (!targetPath) {
    return "No path provided.";
  }
  return electron.shell.openPath(targetPath);
});

ipcMain.handle("audit:list", (_event, scanId?: string) => {
  return store?.listAudits(scanId) || [];
});

ipcMain.handle("tools:list", async () => {
  if (!toolManager) {
    throw new Error("Tool manager is not initialized.");
  }
  return toolManager.listTools();
});

ipcMain.handle("tools:check", async (_event, payload: { tool: string }) => {
  if (!toolManager) {
    throw new Error("Tool manager is not initialized.");
  }
  const result = await toolManager.checkTool(payload.tool);
  await store?.addAudit({
    action: "tool.check",
    actor: "local-user",
    role: "Security Analyst",
    details: `${payload.tool} check => ${result.available ? "available" : "missing"} (${result.message})`,
  });
  return result;
});

ipcMain.handle("tools:install", async (_event, payload: { tool: string }) => {
  if (!toolManager) {
    throw new Error("Tool manager is not initialized.");
  }
  const result = await toolManager.installTool(payload.tool);
  await store?.addAudit({
    action: "tool.install",
    actor: "local-user",
    role: "Security Analyst",
    details: `${payload.tool} install => ${result.success ? "success" : "failed"} (${result.message})`,
  });
  return result;
});

ipcMain.handle("tools:bootstrap", async (_event, payload: { profile: "codebase" | "website" | "ip" | "all"; mode: "core" | "full" }) => {
  if (!toolManager) {
    throw new Error("Tool manager is not initialized.");
  }
  const result = await toolManager.bootstrapProfile(payload.profile, payload.mode);
  await store?.addAudit({
    action: "tool.bootstrap",
    actor: "local-user",
    role: "Security Analyst",
    details: `${payload.profile}/${payload.mode} => ${result.ready}/${result.total} ready (${result.message})`,
  });
  return result;
});

ipcMain.handle("tools:run", async (_event, payload: { tool: string; target: string }) => {
  if (!toolManager) {
    throw new Error("Tool manager is not initialized.");
  }
  const result = await toolManager.runTool(payload.tool, payload.target);
  await store?.addAudit({
    action: "tool.run",
    actor: "local-user",
    role: "Security Analyst",
    details: `${payload.tool} run on ${payload.target} => ${result.success ? "success" : "failed"} (${result.message})`,
  });
  return result;
});

ipcMain.handle("app:resetLocalStateCache", async () => {
  if (!scannerRootPath || !storeFilePath || !toolchainCachePath || !toolRunDirPath) {
    throw new Error("CodeSentinelX paths are not initialized.");
  }

  const storeBackupPath = `${storeFilePath}.reset-${new Date().toISOString().replaceAll(":", "-").replaceAll(".", "-")}.bak`;
  if (fs.existsSync(storeFilePath)) {
    await fs.promises.rename(storeFilePath, storeBackupPath).catch(() => undefined);
  }
  await fs.promises.unlink(`${storeFilePath}.tmp`).catch(() => undefined);

  await fs.promises.rm(toolRunDirPath, { recursive: true, force: true });
  await fs.promises.mkdir(toolRunDirPath, { recursive: true });

  await fs.promises.rm(toolchainCachePath, { recursive: true, force: true });
  await fs.promises.mkdir(toolchainCachePath, { recursive: true });

  const seedMessage = await seedToolchainCache(scannerRootPath, toolchainCachePath);
  process.env.USS_TOOLS_DIR = toolchainCachePath;

  store = await ScanStore.create(storeFilePath);
  scannerBridge = new PythonScannerBridge(scannerRootPath);
  toolManager = new ToolManager(scannerRootPath, toolRunDirPath);

  await store.addAudit({
    action: "app.reset.local_state_cache",
    actor: "local-user",
    role: "Admin",
    details: "Local state and cache reset via Tool Manager.",
  });

  const toolStatus = await toolManager.bootstrapProfile("all", "core");
  log.info(
    `Reset completed. ${seedMessage} Core warmup ready=${toolStatus.ready}/${toolStatus.total}, missing=${toolStatus.missing}.`,
  );

  return {
    success: true,
    message: "Local state and cache reset completed.",
    storeBackupPath: fs.existsSync(storeBackupPath) ? storeBackupPath : "",
    toolchainCachePath,
    seedMessage,
    coreWarmup: {
      ready: toolStatus.ready,
      total: toolStatus.total,
      missing: toolStatus.missing,
      success: toolStatus.success,
    },
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

function resolveToolchainPath(scannerRoot: string): string {
  return path.join(scannerRoot, ".toolchain");
}

function inferTargetKind(target: string): string {
  const value = target.trim();
  if (!value) {
    return "Codebase scan";
  }
  if (/^ssh:\/\//i.test(value)) {
    return "Remote SSH scan";
  }
  try {
    const resolved = path.resolve(value);
    if (fs.existsSync(resolved)) {
      return "Codebase scan";
    }
  } catch {
    // Ignore filesystem probe failure and continue.
  }
  if (/^[a-zA-Z]:[\\/]/.test(value) || value.includes("\\") || value.startsWith(".") || value.startsWith("..")) {
    return "Codebase scan";
  }
  if (
    /^https?:\/\//i.test(value) ||
    /^\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?(?:\/.*)?$/.test(value) ||
    /^localhost(?::\d+)?(?:\/.*)?$/i.test(value) ||
    /^[a-z0-9.-]+\.[a-z]{2,}(?::\d+)?(?:\/.*)?$/i.test(value)
  ) {
    return "Runtime IP/URL scan";
  }
  return "Codebase scan";
}

function isStoppedScanMessage(message: string): boolean {
  const normalized = message.trim().toLowerCase();
  return normalized.includes("scan stopped by user");
}

async function seedToolchainCache(
  scannerRoot: string,
  cacheDir: string,
  additionalSources: string[] = [],
): Promise<string> {
  await fs.promises.mkdir(cacheDir, { recursive: true });
  if (await directoryHasFiles(cacheDir)) {
    return `Toolchain cache already present: ${cacheDir}`;
  }

  const resourceSeed = path.join(process.resourcesPath, "toolchain-seed");
  const envSeed = process.env.CODESENTINELX_TOOLCHAIN_SEED || "";
  const sourceCandidates = [envSeed, resourceSeed, ...additionalSources, path.join(scannerRoot, ".toolchain")]
    .filter(Boolean)
    .map((item) => path.resolve(item));

  for (const source of sourceCandidates) {
    if (source === path.resolve(cacheDir)) {
      continue;
    }
    if (!fs.existsSync(source)) {
      continue;
    }
    if (!(await directoryHasFiles(source))) {
      continue;
    }

    await fs.promises.cp(source, cacheDir, {
      recursive: true,
      force: true,
      errorOnExist: false,
    });
    return `Seeded toolchain cache from ${source} -> ${cacheDir}`;
  }

  return `No bundled toolchain seed found. Cache will be hydrated on demand: ${cacheDir}`;
}

async function directoryHasFiles(dirPath: string): Promise<boolean> {
  try {
    const entries = await fs.promises.readdir(dirPath);
    return entries.length > 0;
  } catch {
    return false;
  }
}
