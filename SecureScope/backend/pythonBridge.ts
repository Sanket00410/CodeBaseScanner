import fs from "node:fs";
import { promises as fsAsync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";

import { ScanProgressPayload, ScanRequest, UniversalScanReport } from "./types";

interface ScanExecutionResult {
  report: UniversalScanReport;
  startedAt: string;
  completedAt: string;
  warnings: string[];
}

export class PythonScannerBridge {
  private readonly scannerRoot: string;
  private readonly pythonPath: string;

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
    const normalizedTarget = normalizeTargetInput(request.projectPath);
    const targetType = inferTargetType(normalizedTarget);

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
        env: {
          ...process.env,
          PYTHONUTF8: "1",
        },
        windowsHide: true,
      });

      const heartbeat = setInterval(() => {
        lastProgress = Math.min(95, lastProgress + 0.5);
        onProgress({
          scanId,
          stage: "running",
          progress: lastProgress,
          message: "Scanner is processing files, dependencies, and toolchain checks.",
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
            onProgress({
              scanId,
              stage: parsed.stage,
              progress: lastProgress,
              currentFile: parsed.currentFile,
              message: parsed.message,
              status: "running",
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

      child.on("error", reject);
      child.on("close", (code) => {
        clearInterval(heartbeat);
        if (streamBuffer.trim()) {
          streamBuffer += "\n";
          drainBuffer();
        }
        if (code === 0) {
          resolve();
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

async function cleanupFile(filePath: string): Promise<void> {
  try {
    await fsAsync.unlink(filePath);
  } catch {
    // Ignore temporary cleanup failures.
  }
}
