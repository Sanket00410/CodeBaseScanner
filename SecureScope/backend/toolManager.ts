import fs from "node:fs";
import { promises as fsAsync } from "node:fs";
import path from "node:path";
import { spawn } from "node:child_process";

export type ToolScanProfile = "codebase" | "website" | "ip";
export type ToolBootstrapMode = "core" | "full";

export interface ToolCatalogItem {
  name: string;
  display_name: string;
  description: string;
  category: string;
  command: string;
  target_modes: string[];
  vulnerability_classes: string[];
  homepage: string;
  integrated: boolean;
  scan_profiles: ToolScanProfile[];
  host_available?: boolean;
  host_source?: string;
  host_command?: string;
  host_message?: string;
}

export interface ToolActionResult {
  tool: string;
  success: boolean;
  available?: boolean;
  source?: string;
  command?: string;
  message: string;
  outputPath?: string;
  summary?: {
    target?: string;
    filesScanned?: number;
    vulnerabilities?: number;
    risk?: string;
  };
  stdout?: string;
  stderr?: string;
}

export interface ToolBootstrapResult {
  profile: ToolScanProfile | "all";
  mode: ToolBootstrapMode;
  success: boolean;
  total: number;
  ready: number;
  missing: number;
  tools: ToolActionResult[];
  message: string;
  stdout?: string;
  stderr?: string;
}

interface CommandResult {
  code: number;
  stdout: string;
  stderr: string;
}

export class ToolManager {
  private readonly scannerRoot: string;
  private readonly pythonPath: string;
  private readonly outputDir: string;
  private coreBootstrapAttempted = false;
  private static readonly CORE_TOOLS = [
    "semgrep",
    "trivy",
    "gitleaks",
    "codeql",
    "bandit",
    "brakeman",
    "checkov",
    "clair",
    "cppcheck",
    "eslint-security",
    "findsecbugs",
    "flawfinder",
    "govulncheck",
    "pip-audit",
    "safety",
    "npm-audit",
    "grype",
    "osv-scanner",
    "hadolint",
    "tfsec",
    "gosec",
    "infer",
    "snyk",
    "sonarqube",
    "spotbugs",
    "owasp-dependency-check",
    "nuclei",
    "nikto",
    "nmap",
    "amass",
    "ffuf",
    "kube-bench",
    "kube-hunter",
    "sqlmap",
    "wapiti",
    "zap-baseline",
  ];

  constructor(scannerRoot: string, outputDir: string, pythonPath?: string) {
    this.scannerRoot = scannerRoot;
    this.pythonPath = pythonPath || resolvePythonExecutable(scannerRoot);
    this.outputDir = outputDir;
    fs.mkdirSync(this.outputDir, { recursive: true });
  }

  async listTools(): Promise<ToolCatalogItem[]> {
    if (!this.coreBootstrapAttempted) {
      this.coreBootstrapAttempted = true;
      await this.ensureCoreToolchainReady().catch(() => undefined);
    }

    const script = [
      "import json",
      "from pathlib import Path",
      "from universal_security_scanner.config import ScannerConfig",
      "from universal_security_scanner.scanner.external.catalog import TOOL_CATALOG",
      "from universal_security_scanner.scanner.external.toolchain import discover_toolchain",
      "",
      "def _profiles(item):",
      "    modes = set(item.target_modes)",
      "    profiles = set()",
      "    if 'codebase' in modes or 'remote-codebase' in modes:",
      "        profiles.add('codebase')",
      "    if 'runtime' in modes:",
      "        profiles.add('website')",
      "        category = (item.category or '').lower()",
      "        name = item.name.lower()",
      "        if any(token in category for token in ('network', 'attack surface', 'kubernetes')):",
      "            profiles.add('ip')",
      "        if name in {'nmap', 'amass', 'kube-bench', 'kube-hunter', 'runtime_http_probe'}:",
      "            profiles.add('ip')",
      "    return sorted(profiles)",
      "",
      "config = ScannerConfig.from_env()",
      "discover_names = [name for name in TOOL_CATALOG.keys() if name != 'runtime_http_probe']",
      "status_map = discover_toolchain(config, discover_names, Path.cwd())",
      "payload=[]",
      "for name,item in TOOL_CATALOG.items():",
      "    if name == 'runtime_http_probe':",
      "        status = {'available': True, 'source': 'builtin', 'command': 'builtin', 'message': 'Built into CodeSentinelX runtime.'}",
      "    elif not bool(item.integrated):",
      "        status = {",
      "            'available': True,",
      "            'source': 'catalog-profile',",
      "            'command': item.command,",
      "            'message': 'Catalog profile is available. Native parser integration may vary by tool/vendor runtime.',",
      "        }",
      "    else:",
      "        status_obj = status_map.get(name)",
      "        status = {",
      "            'available': bool(status_obj.available) if status_obj else False,",
      "            'source': status_obj.source if status_obj else 'unknown',",
      "            'command': status_obj.command if status_obj else item.command,",
      "            'message': status_obj.message if status_obj else '',",
      "        }",
      "    payload.append({",
      "        'name': name,",
      "        'display_name': item.display_name,",
      "        'description': item.description,",
      "        'category': item.category,",
      "        'command': item.command,",
      "        'target_modes': list(item.target_modes),",
      "        'vulnerability_classes': list(item.vulnerability_classes),",
      "        'homepage': item.homepage,",
      "        'integrated': bool(item.integrated),",
      "        'scan_profiles': _profiles(item),",
      "        'host_available': bool(status['available']),",
      "        'host_source': status['source'],",
      "        'host_command': status['command'],",
      "        'host_message': status['message'],",
      "    })",
      "payload.sort(key=lambda x: x['name'])",
      "print(json.dumps(payload))",
    ].join("\n");

    const result = await this.runPython(["-c", script]);
    if (result.code !== 0) {
      throw new Error(result.stderr.trim() || "Failed to load tool catalog.");
    }

    const parsed = JSON.parse(result.stdout || "[]");
    if (!Array.isArray(parsed)) {
      return [];
    }
    return parsed as ToolCatalogItem[];
  }

  async bootstrapProfile(profile: ToolScanProfile | "all", mode: ToolBootstrapMode = "core"): Promise<ToolBootstrapResult> {
    if (profile === "all" && mode === "core") {
      this.coreBootstrapAttempted = true;
    }

    const catalog = await this.listTools();
    const selected = catalog
      .filter((item) => item.name !== "runtime_http_probe")
      .filter((item) => profile === "all" || item.scan_profiles.includes(profile))
      .filter((item) => (mode === "core" ? item.integrated : true));
    const toolNames = [...new Set(selected.map((item) => item.name))];
    const integratedByName = new Set(selected.filter((item) => item.integrated).map((item) => item.name));
    const integratedToolNames = toolNames.filter((name) => integratedByName.has(name));
    const catalogOnlyCount = toolNames.length - integratedToolNames.length;

    if (toolNames.length === 0) {
      return {
        profile,
        mode,
        success: true,
        total: 0,
        ready: 0,
        missing: 0,
        tools: [],
        message: "No tools selected for this profile/mode.",
      };
    }

    let commandResult: CommandResult = { code: 0, stdout: "", stderr: "" };
    if (integratedToolNames.length > 0) {
      commandResult = await this.runPython([
        "-m",
        "universal_security_scanner.cli",
        "bootstrap-tools",
        "--path",
        this.scannerRoot,
        "--tools",
        integratedToolNames.join(","),
      ]);
    }

    const parsedMap = parseBootstrapStatusMap(commandResult.stdout);
    const tools = selected.map((item) => {
      const name = item.name;
      if (!item.integrated) {
        return {
          tool: name,
          success: true,
          available: true,
          source: "catalog-profile",
          command: item.command,
          message: "Catalog profile entry is available. Native parser/installer is vendor-specific.",
        } as ToolActionResult;
      }

      const parsed = parsedMap.get(name.toLowerCase());
      return {
        tool: name,
        success: Boolean(parsed?.available),
        available: Boolean(parsed?.available),
        source: parsed?.source || "",
        command: parsed?.command || "",
        message: parsed?.message || "No tool status details from bootstrap output.",
      } as ToolActionResult;
    });

    const ready = tools.filter((item) => item.available).length;
    const missing = tools.length - ready;
    const commandFailed = commandResult.code !== 0 && commandResult.code !== 2;
    const success = !commandFailed && missing === 0;
    const profileLabel = profile === "all" ? "all profiles" : `${profile} profile`;
    const modeLabel = mode === "core" ? "core integrated toolchain" : "full catalog";
    const catalogSuffix =
      mode === "full" && catalogOnlyCount > 0
        ? ` Catalog-only mapped: ${catalogOnlyCount}.`
        : "";

    return {
      profile,
      mode,
      success,
      total: tools.length,
      ready,
      missing,
      tools,
      message: `Bootstrap completed for ${profileLabel} (${modeLabel}): ${ready}/${tools.length} ready.${catalogSuffix}`,
      stdout: truncate(commandResult.stdout),
      stderr: truncate(commandResult.stderr),
    };
  }

  async checkTool(toolName: string): Promise<ToolActionResult> {
    if (toolName === "runtime_http_probe") {
      return {
        tool: toolName,
        success: true,
        available: true,
        source: "builtin",
        command: "builtin",
        message: "Built-in runtime probe is always available.",
      };
    }

    const result = await this.runPython(
      ["-m", "universal_security_scanner.cli", "bootstrap-tools", "--path", this.scannerRoot, "--tools", toolName],
      {
        USS_AUTO_BOOTSTRAP_TOOLS: "0",
      },
    );

    const parsed = parseBootstrapLine(result.stdout, toolName);
    return {
      tool: toolName,
      success: result.code === 0 || result.code === 2,
      available: parsed.available,
      source: parsed.source,
      command: parsed.command,
      message: parsed.message || result.stderr.trim() || "Tool check completed.",
      stdout: truncate(result.stdout),
      stderr: truncate(result.stderr),
    };
  }

  async installTool(toolName: string): Promise<ToolActionResult> {
    if (toolName === "runtime_http_probe") {
      return {
        tool: toolName,
        success: true,
        available: true,
        source: "builtin",
        command: "builtin",
        message: "Built-in runtime probe does not require installation.",
      };
    }

    const result = await this.runPython([
      "-m",
      "universal_security_scanner.cli",
      "bootstrap-tools",
      "--path",
      this.scannerRoot,
      "--tools",
      toolName,
    ]);

    const parsed = parseBootstrapLine(result.stdout, toolName);
    return {
      tool: toolName,
      success: parsed.available,
      available: parsed.available,
      source: parsed.source,
      command: parsed.command,
      message:
        parsed.message ||
        (parsed.available ? "Tool installed or already available." : result.stderr.trim() || "Tool install failed."),
      stdout: truncate(result.stdout),
      stderr: truncate(result.stderr),
    };
  }

  async runTool(toolName: string, targetInput: string): Promise<ToolActionResult> {
    const catalog = await this.listTools();
    const catalogEntry = catalog.find((item) => item.name === toolName);
    if (catalogEntry && !catalogEntry.integrated) {
      return {
        tool: toolName,
        success: false,
        message:
          "This tool is cataloged for enterprise visibility, but direct normalized execution is not integrated yet.",
      };
    }

    const normalizedTarget = normalizeTargetInput(targetInput);
    const targetType = inferTargetType(normalizedTarget);
    const stamp = new Date().toISOString().replaceAll(":", "-").replaceAll(".", "-");
    const outputPath = path.join(this.outputDir, `toolrun_${toolName}_${stamp}.json`);
    await fsAsync.mkdir(path.dirname(outputPath), { recursive: true });

    const result = await this.runPython(
      [
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
        "vulnerability",
        "--output",
        outputPath,
      ],
      {
        USS_USE_EXTERNAL_TOOLS: "1",
        USS_EXTERNAL_TOOLS: toolName,
        USS_CODEBASE_TOOLS: toolName,
        USS_RUNTIME_TOOLS: toolName,
      },
    );

    if (result.code !== 0) {
      return {
        tool: toolName,
        success: false,
        message: result.stderr.trim() || `Tool run failed for ${toolName}.`,
        stdout: truncate(result.stdout),
        stderr: truncate(result.stderr),
      };
    }

    const summary = parseScanSummary(result.stdout);
    return {
      tool: toolName,
      success: true,
      message: `Tool run completed for ${toolName}.`,
      outputPath,
      summary,
      stdout: truncate(result.stdout),
      stderr: truncate(result.stderr),
    };
  }

  private async runPython(
    args: string[],
    envOverride: Record<string, string> = {},
    timeoutMs = 15 * 60 * 1000,
  ): Promise<CommandResult> {
    return new Promise<CommandResult>((resolve, reject) => {
      const child = spawn(this.pythonPath, args, {
        cwd: this.scannerRoot,
        env: {
          ...process.env,
          ...envOverride,
          PYTHONUTF8: "1",
        },
        windowsHide: true,
      });
      const timer = setTimeout(() => {
        child.kill();
        reject(new Error(`Command timed out after ${Math.floor(timeoutMs / 1000)}s: ${args.join(" ")}`));
      }, timeoutMs);

      let stdout = "";
      let stderr = "";
      child.stdout.on("data", (chunk) => {
        stdout += String(chunk);
      });
      child.stderr.on("data", (chunk) => {
        stderr += String(chunk);
      });
      child.on("error", (error) => {
        clearTimeout(timer);
        reject(error);
      });
      child.on("close", (code) => {
        clearTimeout(timer);
        resolve({
          code: code ?? 1,
          stdout,
          stderr,
        });
      });
    });
  }

  private async ensureCoreToolchainReady(): Promise<void> {
    const tools = ToolManager.CORE_TOOLS.join(",");
    await this.runPython(
      ["-m", "universal_security_scanner.cli", "bootstrap-tools", "--path", this.scannerRoot, "--tools", tools],
      {},
      20 * 60 * 1000,
    );
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
    throw new Error("Target is required to run a tool.");
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
  if (/^localhost(?::\d+)?(?:\/.*)?$/i.test(value)) {
    return "http";
  }
  try {
    const resolved = path.resolve(value);
    if (fs.existsSync(resolved)) {
      return "local";
    }
  } catch {
    // Ignore local resolution errors and continue heuristics.
  }
  if (/^[a-zA-Z]:[\\/]/.test(value) || value.includes("\\") || value.startsWith(".") || value.startsWith("..")) {
    return "local";
  }
  if (/^\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?(?:\/.*)?$/.test(value)) {
    return "http";
  }
  if (/^[a-z0-9.-]+\.[a-z]{2,}(?::\d+)?(?:\/.*)?$/i.test(value)) {
    return "http";
  }
  return "local";
}

function parseBootstrapLine(stdout: string, toolName: string): {
  available: boolean;
  source: string;
  command: string;
  message: string;
} {
  const parsedMap = parseBootstrapStatusMap(stdout);
  const parsed = parsedMap.get(toolName.toLowerCase());
  return parsed || {
    available: false,
    source: "",
    command: "",
    message: "No status output from bootstrap command.",
  };
}

function parseBootstrapStatusMap(stdout: string): Map<string, { available: boolean; source: string; command: string; message: string }> {
  const lines = String(stdout || "").split(/\r?\n/);
  const map = new Map<string, { available: boolean; source: string; command: string; message: string }>();
  const statusPattern = /^\[(OK|MISSING)\]\s+([^\s|]+)\s+\|\s+source=([^|]+)\|\s+command=(.+)$/i;
  let currentTool = "";

  for (const rawLine of lines) {
    const line = rawLine.trim();
    const statusMatch = line.match(statusPattern);
    if (statusMatch) {
      const tool = String(statusMatch[2] || "").trim();
      const key = tool.toLowerCase();
      currentTool = tool;
      map.set(key, {
        available: String(statusMatch[1] || "").toUpperCase() === "OK",
        source: String(statusMatch[3] || "").trim(),
        command: String(statusMatch[4] || "").trim(),
        message: line,
      });
      continue;
    }

    if (line.startsWith("->") && currentTool && map.has(currentTool.toLowerCase())) {
      map.get(currentTool.toLowerCase())!.message = line.replace(/^->\s*/, "").trim();
    }
  }
  return map;
}

function parseScanSummary(stdout: string): { target?: string; filesScanned?: number; vulnerabilities?: number; risk?: string } {
  const lines = stdout.split(/\r?\n/).map((line) => line.trim());
  const target = lines.find((line) => line.startsWith("Target:"))?.replace(/^Target:\s*/, "");
  const filesRaw = lines.find((line) => line.startsWith("Files scanned:"))?.replace(/^Files scanned:\s*/, "");
  const vulnRaw = lines
    .find((line) => line.startsWith("Total vulnerabilities:"))
    ?.replace(/^Total vulnerabilities:\s*/, "");
  const risk = lines.find((line) => line.startsWith("Risk score:"))?.replace(/^Risk score:\s*/, "");
  const filesScanned = filesRaw ? Number.parseInt(filesRaw, 10) : undefined;
  const vulnerabilities = vulnRaw ? Number.parseInt(vulnRaw, 10) : undefined;
  return { target, filesScanned, vulnerabilities, risk };
}

function truncate(value: string, maxLength = 1600): string {
  const text = String(value || "").trim();
  if (text.length <= maxLength) {
    return text;
  }
  return `${text.slice(0, maxLength)}...`;
}
