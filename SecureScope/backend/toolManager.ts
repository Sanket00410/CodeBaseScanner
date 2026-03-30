import fs from "node:fs";
import path from "node:path";
import { spawn } from "node:child_process";

export type ToolScanProfile = "codebase";
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

  constructor(scannerRoot: string, outputDir: string, pythonPath?: string) {
    this.scannerRoot = scannerRoot;
    this.pythonPath = pythonPath || resolvePythonExecutable(scannerRoot);
    this.outputDir = outputDir;
    fs.mkdirSync(this.outputDir, { recursive: true });
  }

  async listTools(): Promise<ToolCatalogItem[]> {
    const script = [
      "import json",
      "from universal_security_scanner.scanner.external.catalog import TOOL_CATALOG",
      "ACTIVE = {",
      "    'bandit','brakeman','checkov','clair','codeql','eslint-security','gitleaks','gosec',",
      "    'govulncheck','grype','hadolint','infer','osv-scanner','semgrep','tfsec'",
      "}",
      "payload=[]",
      "for name,item in TOOL_CATALOG.items():",
      "    if name not in ACTIVE:",
      "        continue",
      "    modes = set(item.target_modes)",
      "    if 'codebase' not in modes and 'remote-codebase' not in modes:",
      "        continue",
      "    payload.append({",
      "        'name': name,",
      "        'display_name': item.display_name,",
      "        'description': item.description,",
      "        'category': item.category,",
      "        'command': item.command,",
      "        'target_modes': [mode for mode in item.target_modes if mode in ('codebase', 'remote-codebase')],",
      "        'vulnerability_classes': list(item.vulnerability_classes),",
      "        'homepage': item.homepage,",
      "        'integrated': bool(item.integrated),",
      "        'scan_profiles': ['codebase'],",
      "        'host_available': False,",
      "        'host_source': 'disabled-by-policy',",
      "        'host_command': item.command,",
      "        'host_message': 'Code analysis catalog only. App-managed external binaries are disabled by policy.',",
      "    })",
      "payload.sort(key=lambda x: x['name'])",
      "print(json.dumps(payload))",
    ].join("\n");

    const result = await this.runPython(["-c", script]);
    if (result.code !== 0) {
      throw new Error(result.stderr.trim() || "Failed to load code-analysis catalog.");
    }

    const parsed = JSON.parse(result.stdout || "[]");
    if (!Array.isArray(parsed)) {
      return [];
    }
    return parsed as ToolCatalogItem[];
  }

  async bootstrapProfile(profile: ToolScanProfile | "all", mode: ToolBootstrapMode = "core"): Promise<ToolBootstrapResult> {
    const catalog = await this.listTools();
    const selected = catalog
      .filter((item) => profile === "all" || item.scan_profiles.includes(profile))
      .filter((item) => (mode === "core" ? item.integrated : true));

    const tools = selected.map((item) => ({
      tool: item.name,
      success: false,
      available: false,
      source: "disabled-by-policy",
      command: item.command,
      message: "Code analysis catalog is visibility-only. Binary bootstrap is disabled by security policy.",
    })) as ToolActionResult[];

    return {
      profile,
      mode,
      success: false,
      total: tools.length,
      ready: 0,
      missing: tools.length,
      tools,
      message: "CodeSentinelX desktop is locked to native codebase analysis. External tool provisioning is disabled.",
    };
  }

  async checkTool(toolName: string): Promise<ToolActionResult> {
    return {
      tool: toolName,
      success: false,
      available: false,
      source: "disabled-by-policy",
      command: toolName,
      message: "Code analysis catalog is visibility-only. External tool checks are disabled by security policy.",
    };
  }

  async installTool(toolName: string): Promise<ToolActionResult> {
    return {
      tool: toolName,
      success: false,
      available: false,
      source: "disabled-by-policy",
      command: toolName,
      message: "External tool installation is disabled. Built-in native code-analysis rules are the only supported runtime.",
    };
  }

  async runTool(toolName: string, _targetInput: string): Promise<ToolActionResult> {
    return {
      tool: toolName,
      success: false,
      available: false,
      source: "disabled-by-policy",
      command: toolName,
      message: "Single-tool execution is disabled. Run the main codebase scan using native rules instead.",
    };
  }

  private async runPython(args: string[]): Promise<CommandResult> {
    return new Promise<CommandResult>((resolve, reject) => {
      const child = spawn(this.pythonPath, args, {
        cwd: this.scannerRoot,
        env: {
          ...process.env,
          PYTHONUTF8: "1",
        },
        windowsHide: true,
      });
      const timer = setTimeout(() => {
        child.kill();
        reject(new Error(`Command timed out after 60s: ${args.join(" ")}`));
      }, 60 * 1000);

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
