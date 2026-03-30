import fs from "node:fs";
import { promises as fsAsync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { ChildProcessWithoutNullStreams, spawn } from "node:child_process";

import { ScanControlActionResult, ScanProgressPayload, ScanRequest, UniversalScanReport } from "./types";

interface ScanExecutionResult {
  report: UniversalScanReport;
  startedAt: string;
  completedAt: string;
  warnings: string[];
}

interface ActiveScanState {
  child: ChildProcessWithoutNullStreams;
  controlFile: string;
  onProgress: (progress: ScanProgressPayload) => void;
  lastProgress: number;
  paused: boolean;
  stopRequested: boolean;
}

type ScanStatus = "running" | "paused" | "completed" | "failed" | "stopped";

export class PythonScannerBridge {
  private readonly scannerRoot: string;
  private readonly pythonPath: string;
  private readonly activeScans = new Map<string, ActiveScanState>();

  constructor(scannerRoot: string, pythonPath?: string) {
    this.scannerRoot = scannerRoot;
    this.pythonPath = pythonPath || resolvePythonExecutable(scannerRoot);
  }

  async runScan(
    scanId: string,
    request: ScanRequest,
    onProgress: (progress: ScanProgressPayload) => void,
  ): Promise<ScanExecutionResult> {
    const startedAt = new Date().toISOString();
    const outputFile = path.join(os.tmpdir(), `codesentinelx-${scanId}-combined.json`);
    const controlFile = path.join(os.tmpdir(), `codesentinelx-${scanId}-control.json`);
    await this.setControlState(controlFile, "running");

    const normalizedTarget = normalizeTargetInput(request.projectPath);
    const scanPreset = resolveRoleScanPreset(request.role);
    const scanEnv = buildScanEnvironment(this.scannerRoot, controlFile, scanPreset, request.role, request.scmContext);

    const args = [
      "-m",
      "codesentinelx_engine.cli",
      "scan",
      "--path",
      normalizedTarget,
      "--target-type",
      "local",
      "--format",
      "json",
      "--report-type",
      "combined",
      "--output",
      outputFile,
    ];

    const stdoutChunks: string[] = [];
    const stderrChunks: string[] = [];
    let streamBuffer = "";
    let lastProgress = 1;

    await new Promise<void>((resolve, reject) => {
      const child = spawn(this.pythonPath, args, {
        cwd: this.scannerRoot,
        env: scanEnv,
        windowsHide: true,
      });

      this.activeScans.set(scanId, {
        child,
        controlFile,
        onProgress,
        lastProgress,
        paused: false,
        stopRequested: false,
      });

      const heartbeat = setInterval(() => {
        const state = this.activeScans.get(scanId);
        if (!state || state.stopRequested) {
          return;
        }
        if (state.paused) {
          state.onProgress({
            scanId,
            stage: "paused",
            progress: state.lastProgress,
            message: "Scan is paused.",
            status: "paused",
          });
          return;
        }
        state.lastProgress = Math.min(95, state.lastProgress + 0.5);
        lastProgress = state.lastProgress;
        state.onProgress({
          scanId,
          stage: "running",
          progress: state.lastProgress,
          message: `Scanner is processing local files and secure coding rules in native codebase mode (${scanPreset}).`,
          status: "running",
        });
      }, 3000);

      const drainBuffer = (): void => {
        const parts = streamBuffer.split(/\r\n|\n|\r/);
        streamBuffer = parts.pop() ?? "";
        for (const rawLine of parts) {
          const line = stripAnsi(rawLine).trim();
          if (!line) {
            continue;
          }

          const parsed = parseProgressLine(line);
          if (parsed) {
            lastProgress = Math.max(lastProgress, parsed.progress);
            const state = this.activeScans.get(scanId);
            if (state) {
              state.lastProgress = lastProgress;
            }
            onProgress({
              scanId,
              stage: parsed.stage,
              progress: lastProgress,
              currentFile: parsed.currentFile,
              message: parsed.message,
              status: stageToStatus(parsed.stage),
            });
            continue;
          }

          onProgress({
            scanId,
            stage: "running",
            progress: lastProgress,
            message: line,
            status: "running",
          });
        }
      };

      child.stdout.on("data", (buffer) => {
        const text = String(buffer);
        stdoutChunks.push(text);
        streamBuffer += text;
        drainBuffer();
      });

      child.stderr.on("data", (buffer) => {
        stderrChunks.push(String(buffer));
      });

      child.on("error", (error) => {
        clearInterval(heartbeat);
        this.activeScans.delete(scanId);
        reject(error);
      });

      child.on("close", (code) => {
        clearInterval(heartbeat);
        if (streamBuffer.trim()) {
          streamBuffer += "\n";
          drainBuffer();
        }

        const state = this.activeScans.get(scanId);
        this.activeScans.delete(scanId);
        void cleanupFile(controlFile);

        if (code === 0) {
          resolve();
          return;
        }

        if (state?.stopRequested) {
          reject(new Error("Scan stopped by user."));
          return;
        }

        const stderr = stderrChunks.join("").trim();
        reject(new Error(stderr || `Scanner process exited with code ${code}`));
      });
    });

    const outputRaw = await fsAsync.readFile(outputFile, "utf-8");
    const report = JSON.parse(outputRaw) as UniversalScanReport;
    const completedAt = new Date().toISOString();
    const warnings = extractWarnings(stdoutChunks.join(""));

    onProgress({
      scanId,
      stage: "completed",
      progress: 100,
      message: "Scan completed",
      status: "completed",
    });

    cleanupFile(outputFile).catch(() => undefined);
    return { report, startedAt, completedAt, warnings };
  }

  async pauseScan(scanId: string): Promise<ScanControlActionResult> {
    const state = this.activeScans.get(scanId);
    if (!state) {
      return {
        scanId,
        success: false,
        state: "running",
        message: "No active scan found for pause.",
      };
    }

    state.paused = true;
    await this.setControlState(state.controlFile, "paused");
    state.onProgress({
      scanId,
      stage: "paused",
      progress: state.lastProgress,
      message: "Scan paused by user.",
      status: "paused",
    });
    return {
      scanId,
      success: true,
      state: "paused",
      message: "Scan paused.",
    };
  }

  async resumeScan(scanId: string): Promise<ScanControlActionResult> {
    const state = this.activeScans.get(scanId);
    if (!state) {
      return {
        scanId,
        success: false,
        state: "running",
        message: "No active scan found for resume.",
      };
    }

    state.paused = false;
    await this.setControlState(state.controlFile, "running");
    state.onProgress({
      scanId,
      stage: "running",
      progress: state.lastProgress,
      message: "Scan resumed by user.",
      status: "running",
    });
    return {
      scanId,
      success: true,
      state: "running",
      message: "Scan resumed.",
    };
  }

  async stopScan(scanId: string): Promise<ScanControlActionResult> {
    const state = this.activeScans.get(scanId);
    if (!state) {
      return {
        scanId,
        success: false,
        state: "stopped",
        message: "No active scan found for stop.",
      };
    }

    state.stopRequested = true;
    state.paused = false;
    await this.setControlState(state.controlFile, "stopped");
    state.onProgress({
      scanId,
      stage: "stopped",
      progress: state.lastProgress,
      message: "Stopping scan...",
      status: "stopped",
    });
    await terminateProcessTree(state.child.pid);

    return {
      scanId,
      success: true,
      state: "stopped",
      message: "Stop signal sent.",
    };
  }

  private async setControlState(controlFile: string, state: "running" | "paused" | "stopped"): Promise<void> {
    const payload = {
      state,
      updated_at: new Date().toISOString(),
    };
    await fsAsync.writeFile(controlFile, JSON.stringify(payload), "utf-8");
  }
}

function buildScanEnvironment(
  scannerRoot: string,
  controlFile: string,
  scanPreset: "fast" | "standard" | "deep",
  role?: ScanRequest["role"],
  scmContext?: ScanRequest["scmContext"],
): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    PYTHONUTF8: "1",
    USS_SCAN_CONTROL_FILE: controlFile,
    USS_SCAN_ROLE: role || process.env.USS_SCAN_ROLE || "Security Analyst",
    USS_MAX_FINDINGS: "0",
    USS_USE_EXTERNAL_TOOLS: process.env.USS_USE_EXTERNAL_TOOLS || "1",
    USS_AUTO_BOOTSTRAP_TOOLS: "0",
  };
  env.USS_EXTERNAL_TOOL_TIMEOUT_SECONDS = env.USS_EXTERNAL_TOOL_TIMEOUT_SECONDS || "900";
  for (const key of Object.keys(env)) {
    if (/^USS_(?:.*_)?TOOLS$/.test(key) || key === "USS_TOOLS_DIR") {
      delete env[key];
    }
  }
  delete env.USS_DIFF_BASE_REF;
  delete env.USS_DIFF_HEAD_REF;
  delete env.USS_CHANGED_FILES_FILE;
  delete env.USS_CHANGED_FILES_JSON;
  delete env.USS_CHANGED_LINES_JSON;
  env.USS_REPORT_CHAIN_FILE = path.join(scannerRoot, "exports", ".integrity", "report_chain.json");
  env.USS_SUPPRESSION_LIFECYCLE_FILE = path.join(scannerRoot, "exports", ".integrity", "suppression_lifecycle.json");
  env.USS_SCAN_CACHE_FILE = env.USS_SCAN_CACHE_FILE || path.join(scannerRoot, "exports", ".integrity", "scan_cache.json");
  env.USS_QUALITY_BENCHMARK_FILE = env.USS_QUALITY_BENCHMARK_FILE || path.join(scannerRoot, "exports", ".integrity", "benchmark_truth_set.json");
  const autoCodeqlSearchPath = resolveCodeqlSearchPath(scannerRoot);
  if (autoCodeqlSearchPath && !env.USS_CODEQL_SEARCH_PATH) {
    env.USS_CODEQL_SEARCH_PATH = autoCodeqlSearchPath;
  }
  if (autoCodeqlSearchPath && !env.CODEQL_SEARCH_PATH) {
    env.CODEQL_SEARCH_PATH = autoCodeqlSearchPath;
  }
  if (scmContext) {
    if (scmContext.diffBaseRef) {
      env.USS_DIFF_BASE_REF = String(scmContext.diffBaseRef);
    }
    if (scmContext.diffHeadRef) {
      env.USS_DIFF_HEAD_REF = String(scmContext.diffHeadRef);
    }
    if (scmContext.changedFilesFile) {
      env.USS_CHANGED_FILES_FILE = String(scmContext.changedFilesFile);
    }
    if (scmContext.changedFilesJson) {
      env.USS_CHANGED_FILES_JSON = String(scmContext.changedFilesJson);
    }
    if (scmContext.changedLinesJson) {
      env.USS_CHANGED_LINES_JSON = String(scmContext.changedLinesJson);
    }
  }
  applyScanPreset(env, scanPreset, role);

  return env;
}

function applyScanPreset(
  env: NodeJS.ProcessEnv,
  preset: "fast" | "standard" | "deep",
  role?: ScanRequest["role"],
): void {
  const logicalCores = Math.max(2, Math.min(16, os.cpus().length || 4));
  const toolPresets: Record<NonNullable<ScanRequest["scanPreset"]>, string[]> = {
    fast: ["semgrep", "gitleaks", "bandit", "checkov"],
    standard: [
      "semgrep",
      "gitleaks",
      "bandit",
      "checkov",
      "gosec",
      "govulncheck",
      "eslint-security",
      "hadolint",
      "tfsec",
      "grype",
      "osv-scanner",
    ],
    deep: [
      "bandit",
      "checkov",
      "codeql",
      "gitleaks",
      "gosec",
      "govulncheck",
      "grype",
      "hadolint",
      "infer",
      "osv-scanner",
      "semgrep",
      "tfsec",
    ],
  };
  const roleScopedTools = resolveRoleScopedTools(role, preset, toolPresets);
  env.USS_SCAN_PRESET = preset;
  if (!env.USS_CODEBASE_TOOLS) {
    env.USS_CODEBASE_TOOLS = roleScopedTools.join(",");
  }
  if (!env.USS_EXTERNAL_TOOLS) {
    env.USS_EXTERNAL_TOOLS = env.USS_CODEBASE_TOOLS;
  }
  if (!env.USS_DEPENDENCY_CORROBORATION) {
    const normalizedRole = String(role || "Security Analyst").trim().toLowerCase();
    env.USS_DEPENDENCY_CORROBORATION = normalizedRole === "admin" || normalizedRole === "administrator"
      ? preset === "deep" ? "1" : "0"
      : "0";
  }
  if (!env.USS_TOOL_WORKERS) {
    env.USS_TOOL_WORKERS = String(Math.max(2, Math.min(8, logicalCores)));
  }
  if (!env.USS_EXTERNAL_TOOL_WORKERS) {
    env.USS_EXTERNAL_TOOL_WORKERS = env.USS_TOOL_WORKERS;
  }
  if (!env.USS_SCAN_CACHE_ENABLED) {
    env.USS_SCAN_CACHE_ENABLED = "1";
  }
  if (preset === "fast") {
    env.USS_FILE_SCAN_WORKERS = String(Math.max(4, Math.min(12, logicalCores)));
    env.USS_MAX_FILE_SIZE_KB = "512";
    env.USS_USE_NATIVE_DEPENDENCY_ANALYSIS = "1";
    env.USS_USE_PROJECT_RULES = "0";
    env.USS_EXTERNAL_TOOL_TIMEOUT_SECONDS = env.USS_EXTERNAL_TOOL_TIMEOUT_SECONDS || "180";
    env.USS_NATIVE_ANALYSIS_FAMILIES = env.USS_NATIVE_ANALYSIS_FAMILIES || "sql-injection,command-injection,path-traversal,unsafe-eval,xss,prototype-pollution";
    env.USS_ACTIVE_POC_MODE = "0";
    env.USS_ACTIVE_POC_MAX_FINDINGS = "0";
    return;
  }
  if (preset === "deep") {
    env.USS_FILE_SCAN_WORKERS = String(Math.max(4, Math.min(10, logicalCores)));
    env.USS_MAX_FILE_SIZE_KB = "2048";
    env.USS_USE_NATIVE_DEPENDENCY_ANALYSIS = "1";
    env.USS_USE_PROJECT_RULES = "1";
    env.USS_EXTERNAL_TOOL_TIMEOUT_SECONDS = env.USS_EXTERNAL_TOOL_TIMEOUT_SECONDS || "900";
    env.USS_NATIVE_ANALYSIS_FAMILIES = env.USS_NATIVE_ANALYSIS_FAMILIES || "";
    env.USS_ACTIVE_POC_MODE = "1";
    env.USS_ACTIVE_POC_MAX_FINDINGS = "0";
    return;
  }
  env.USS_FILE_SCAN_WORKERS = String(Math.max(4, Math.min(10, logicalCores)));
  env.USS_MAX_FILE_SIZE_KB = "1024";
  env.USS_USE_NATIVE_DEPENDENCY_ANALYSIS = "1";
  env.USS_USE_PROJECT_RULES = "1";
  env.USS_EXTERNAL_TOOL_TIMEOUT_SECONDS = env.USS_EXTERNAL_TOOL_TIMEOUT_SECONDS || "300";
  env.USS_NATIVE_ANALYSIS_FAMILIES = env.USS_NATIVE_ANALYSIS_FAMILIES || "sql-injection,command-injection,path-traversal,unsafe-eval,xss,prototype-pollution,server-side-request-forgery,open-redirect,template-injection,insecure-deserialization";
  env.USS_ACTIVE_POC_MODE = "1";
  env.USS_ACTIVE_POC_MAX_FINDINGS = "80";
}

function resolveCodeqlSearchPath(scannerRoot: string): string {
  const explicit = String(process.env.USS_CODEQL_SEARCH_PATH || process.env.CODEQL_SEARCH_PATH || "").trim();
  if (explicit) {
    return explicit;
  }
  const candidates = [
    path.join(scannerRoot, ".toolchain", "codeql", "packs"),
    path.join(scannerRoot, ".toolchain", "codeql", "codeql-repo"),
    path.join(scannerRoot, ".toolchain", "codeql", "codeql-main"),
    path.join(scannerRoot, ".toolchain", "codeql", "codeql"),
  ];
  const valid = candidates.filter((item) => fs.existsSync(item));
  if (valid.length === 0) {
    return "";
  }
  return valid.join(path.delimiter);
}

function resolveRoleScopedTools(
  role: ScanRequest["role"] | undefined,
  preset: "fast" | "standard" | "deep",
  basePresets: Record<NonNullable<ScanRequest["scanPreset"]>, string[]>,
): string[] {
  const normalized = String(role || "Security Analyst").trim().toLowerCase();
  const base = [...basePresets[preset]];
  if (normalized === "admin" || normalized === "administrator") {
    return base;
  }
  if (normalized === "security analyst" || normalized === "securityanalyst") {
    return base.filter((tool) => !["codeql", "grype"].includes(tool));
  }
  if (normalized === "developer") {
    return [
      "semgrep",
      "bandit",
      "eslint-security",
      "gosec",
      "checkov",
      "hadolint",
      "gitleaks",
    ];
  }
  if (normalized === "auditor") {
    return [
      "checkov",
      "tfsec",
      "hadolint",
      "gitleaks",
      "osv-scanner",
    ];
  }
  if (normalized === "management" || normalized === "manager" || normalized === "board") {
    return ["semgrep", "gitleaks", "checkov"];
  }
  return base;
}

function resolveRoleScanPreset(role?: ScanRequest["role"]): "fast" | "standard" | "deep" {
  const normalized = String(role || "Security Analyst").trim().toLowerCase();
  switch (normalized) {
    case "admin":
    case "administrator":
      return "deep";
    case "developer":
    case "auditor":
    case "management":
    case "manager":
    case "board":
      return "fast";
    case "security analyst":
    case "securityanalyst":
    default:
      return "standard";
  }
}

function resolvePythonExecutable(scannerRoot: string): string {
  const envPython = process.env.CODESENTINELX_PYTHON;
  if (envPython && fs.existsSync(envPython)) {
    return envPython;
  }

  const candidates = [
    path.join(scannerRoot, ".venv", "Scripts", "python.exe"),
    path.join(scannerRoot, ".venv", "bin", "python"),
    "python",
  ];

  for (const candidate of candidates) {
    if (candidate === "python" || fs.existsSync(candidate)) {
      return candidate;
    }
  }
  return "python";
}

function normalizeTargetInput(rawTarget: string): string {
  const target = rawTarget.trim();
  if (!target) {
    throw new Error("Codebase folder is required.");
  }
  if (
    /^ssh:\/\//i.test(target) ||
    /^https?:\/\//i.test(target) ||
    /^\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?(?:\/.*)?$/.test(target) ||
    /^localhost(?::\d+)?(?:\/.*)?$/i.test(target) ||
    /^[a-z0-9.-]+\.[a-z]{2,}(?::\d+)?(?:\/.*)?$/i.test(target)
  ) {
    throw new Error("Only local codebase folders are supported. Website, IP, and SSH targets are disabled.");
  }
  const resolved = path.resolve(target);
  if (!fs.existsSync(resolved)) {
    throw new Error("Selected codebase folder does not exist.");
  }
  let stats: fs.Stats;
  try {
    stats = fs.statSync(resolved);
  } catch {
    throw new Error("Selected codebase folder is not accessible.");
  }
  if (!stats.isDirectory()) {
    throw new Error("Only directories can be scanned in codebase-only mode.");
  }
  return resolved;
}

function parseProgressLine(line: string): { progress: number; stage: string; currentFile?: string; message: string } | null {
  const match = line.match(/^\[\s*(\d+(?:\.\d+)?)%\]\s*([^|]+?)(?:\s*\|\s*([^|]+))?(?:\s*\|\s*(.+))?$/);
  if (!match) {
    return null;
  }

  const progress = Number.parseFloat(match[1] || "0");
  const stage = (match[2] || "scanning").trim();
  const currentFile = (match[3] || "").trim();
  const message = (match[4] || stage).trim();

  return {
    progress: Number.isFinite(progress) ? progress : 0,
    stage,
    currentFile: currentFile || undefined,
    message,
  };
}

function stageToStatus(stage: string): ScanStatus {
  const normalized = stage.trim().toLowerCase();
  if (normalized.includes("pause")) {
    return "paused";
  }
  if (normalized.includes("stop")) {
    return "stopped";
  }
  if (normalized.includes("fail") || normalized.includes("error")) {
    return "failed";
  }
  if (normalized === "completed" || normalized.includes("complete")) {
    return "completed";
  }
  return "running";
}

function stripAnsi(value: string): string {
  return value.replace(/\u001b\[[0-9;]*m/g, "");
}

function extractWarnings(stdout: string): string[] {
  const warningsSection = stdout.split("Warnings:");
  if (warningsSection.length < 2) {
    return [];
  }
  return warningsSection[1]
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.startsWith("-"))
    .map((line) => line.replace(/^-+\s*/, ""));
}

async function terminateProcessTree(pid: number | undefined): Promise<void> {
  if (!pid || pid <= 0) {
    return;
  }
  if (process.platform === "win32") {
    await new Promise<void>((resolve) => {
      const killer = spawn("taskkill", ["/PID", String(pid), "/T", "/F"], { windowsHide: true });
      killer.on("error", () => resolve());
      killer.on("close", () => resolve());
    });
    return;
  }
  try {
    process.kill(pid, "SIGTERM");
  } catch {
    // Ignore process kill errors.
  }
}

async function cleanupFile(filePath: string): Promise<void> {
  try {
    await fsAsync.unlink(filePath);
  } catch {
    // Ignore temporary cleanup failures.
  }
}

