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
    const targetType = inferTargetType(normalizedTarget);
    const scanEnv = buildScanEnvironment(controlFile, targetType, request);

    const args = [
      "-m",
      "universal_security_scanner.cli",
      "scan",
      "--path",
      normalizedTarget,
      "--target-type",
      targetType,
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
          message: "Scanner is processing files, dependencies, runtime endpoints, and toolchain checks.",
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

function buildScanEnvironment(controlFile: string, targetType: "local" | "http" | "ssh", request: ScanRequest): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    PYTHONUTF8: "1",
    USS_SCAN_CONTROL_FILE: controlFile,
    USS_MAX_FINDINGS: "0",
  };

  if (targetType === "http") {
    // Runtime scans are discovery-heavy (API + endpoint crawl), so defaults are deeper than codebase mode.
    env.USS_RUNTIME_MAX_URLS = env.USS_RUNTIME_MAX_URLS || "260";
    env.USS_RUNTIME_CRAWL_DEPTH = env.USS_RUNTIME_CRAWL_DEPTH || "3";
    env.USS_RUNTIME_CRAWL_MAX_PAGES = env.USS_RUNTIME_CRAWL_MAX_PAGES || "220";
    env.USS_RUNTIME_TOOL_TARGET_LIMIT = env.USS_RUNTIME_TOOL_TARGET_LIMIT || "160";
    env.USS_RUNTIME_NUCLEI_MAX_TARGETS = env.USS_RUNTIME_NUCLEI_MAX_TARGETS || "140";
    env.USS_EXTERNAL_TOOL_TIMEOUT_SECONDS = env.USS_EXTERNAL_TOOL_TIMEOUT_SECONDS || "900";
    env.USS_RUNTIME_NUCLEI_TIMEOUT_SECONDS = env.USS_RUNTIME_NUCLEI_TIMEOUT_SECONDS || "1200";
    env.USS_REMOTE_HTTP_TIMEOUT_SECONDS = env.USS_REMOTE_HTTP_TIMEOUT_SECONDS || "10";

    const runtimeAuth = request.runtimeAuth || {};
    const token = sanitizeEnvValue(runtimeAuth.token);
    const cookie = sanitizeEnvValue(runtimeAuth.cookie);
    const headerName = sanitizeHeaderName(runtimeAuth.headerName);
    const headerValue = sanitizeEnvValue(runtimeAuth.headerValue);

    if (token) {
      env.USS_RUNTIME_AUTH_TOKEN = token;
    } else {
      delete env.USS_RUNTIME_AUTH_TOKEN;
    }

    if (cookie) {
      env.USS_RUNTIME_AUTH_COOKIE = cookie;
    } else {
      delete env.USS_RUNTIME_AUTH_COOKIE;
    }

    if (headerName && headerValue) {
      env.USS_RUNTIME_AUTH_HEADER_NAME = headerName;
      env.USS_RUNTIME_AUTH_HEADER_VALUE = headerValue;
    } else {
      delete env.USS_RUNTIME_AUTH_HEADER_NAME;
      delete env.USS_RUNTIME_AUTH_HEADER_VALUE;
    }
  }

  return env;
}

function sanitizeEnvValue(value: string | undefined, maxLength = 4096): string {
  const normalized = String(value || "").trim();
  if (!normalized) {
    return "";
  }
  return normalized.slice(0, maxLength);
}

function sanitizeHeaderName(value: string | undefined): string {
  const normalized = String(value || "").trim();
  if (!normalized) {
    return "";
  }
  const allowed = normalized.match(/^[A-Za-z0-9-]{1,120}$/);
  return allowed ? normalized : "";
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
    throw new Error("Scan target is required.");
  }
  const targetType = inferTargetType(target);
  if (targetType === "local") {
    return path.resolve(target);
  }
  return target;
}

function inferTargetType(target: string): "local" | "http" | "ssh" {
  const value = target.trim();
  if (!value) {
    return "local";
  }
  if (/^ssh:\/\//i.test(value)) {
    return "ssh";
  }
  if (/^https?:\/\//i.test(value)) {
    return "http";
  }
  try {
    const resolved = path.resolve(value);
    if (fs.existsSync(resolved)) {
      return "local";
    }
  } catch {
    // Ignore filesystem lookup failures and continue with heuristics.
  }
  if (/^[a-zA-Z]:[\\/]/.test(value) || value.includes("\\") || value.startsWith(".") || value.startsWith("..")) {
    return "local";
  }
  if (/^\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?(?:\/.*)?$/.test(value)) {
    return "http";
  }
  if (/^localhost(?::\d+)?(?:\/.*)?$/i.test(value)) {
    return "http";
  }
  if (/^[a-z0-9.-]+\.[a-z]{2,}(?::\d+)?(?:\/.*)?$/i.test(value)) {
    return "http";
  }
  return "local";
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
