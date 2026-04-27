import fs from "node:fs";
import path from "node:path";

import {
  ThreatModelDataFlow,
  ThreatModelEntryPoint,
  ThreatModelReport,
  ThreatModelRequest,
  ThreatModelResult,
  ThreatModelThreat,
  ThreatModelTrustBoundary,
} from "./types";

type FileSample = {
  filePath: string;
  relativePath: string;
  content: string;
  language: string;
};

const SOURCE_EXTENSIONS = new Set([
  ".ts",
  ".tsx",
  ".js",
  ".jsx",
  ".mjs",
  ".cjs",
  ".py",
  ".go",
  ".java",
  ".cs",
  ".rb",
  ".php",
  ".json",
  ".yml",
  ".yaml",
  ".md",
  ".txt",
  ".toml",
  ".ini",
  ".cfg",
  ".xml",
]);

const IGNORE_SEGMENTS = new Set([
  ".git",
  "node_modules",
  "dist",
  "build",
  "out",
  "release",
  "coverage",
  "__pycache__",
  "venv",
  ".venv",
  "env",
  ".env",
  "target",
  "bin",
  "obj",
  "vendor",
  "logs",
  "exports",
]);

function toPosixPath(input: string): string {
  return String(input || "").replaceAll("\\", "/");
}

function fileLanguage(filePath: string): string {
  const ext = path.extname(filePath).toLowerCase();
  switch (ext) {
    case ".ts":
    case ".tsx":
      return "typescript";
    case ".js":
    case ".jsx":
    case ".mjs":
    case ".cjs":
      return "javascript";
    case ".py":
      return "python";
    case ".go":
      return "go";
    case ".java":
      return "java";
    case ".cs":
      return "csharp";
    case ".rb":
      return "ruby";
    case ".php":
      return "php";
    default:
      return "text";
  }
}

function isIgnoredPathSegment(segment: string): boolean {
  const normalized = segment.trim().toLowerCase();
  return IGNORE_SEGMENTS.has(normalized);
}

async function collectFiles(rootPath: string, maxFiles = 240): Promise<string[]> {
  const rootStat = await fs.promises.stat(rootPath).catch(() => null);
  if (!rootStat) {
    return [];
  }

  if (rootStat.isFile()) {
    return [rootPath];
  }

  const queue = [rootPath];
  const results: string[] = [];
  while (queue.length > 0 && results.length < maxFiles) {
    const current = queue.shift()!;
    const entries = await fs.promises.readdir(current, { withFileTypes: true }).catch(() => []);
    for (const entry of entries) {
      if (results.length >= maxFiles) {
        break;
      }
      if (isIgnoredPathSegment(entry.name)) {
        continue;
      }
      const fullPath = path.join(current, entry.name);
      if (entry.isDirectory()) {
        queue.push(fullPath);
        continue;
      }
      if (!entry.isFile()) {
        continue;
      }
      if (!SOURCE_EXTENSIONS.has(path.extname(entry.name).toLowerCase())) {
        continue;
      }
      results.push(fullPath);
    }
  }
  return results;
}

async function safeReadText(filePath: string): Promise<string> {
  const stat = await fs.promises.stat(filePath).catch(() => null);
  if (!stat || !stat.isFile() || stat.size > 350_000) {
    return "";
  }
  return fs.promises.readFile(filePath, "utf-8").catch(() => "");
}

function uniqueValues(items: string[]): string[] {
  return [...new Set(items.map((item) => item.trim()).filter(Boolean))];
}

function normalizeExposure(text: string): "Public" | "Authenticated" | "Internal" {
  const normalized = text.toLowerCase();
  if (normalized.includes("public")) {
    return "Public";
  }
  if (normalized.includes("auth")) {
    return "Authenticated";
  }
  return "Internal";
}

function detectApplicationType(samples: FileSample[]): string {
  const joined = samples.map((sample) => `${sample.relativePath}\n${sample.content.slice(0, 4000)}`).join("\n");
  const lower = joined.toLowerCase();
  const hasElectron = lower.includes("electron/main") || lower.includes("contextbridge") || lower.includes("ipcmain");
  const hasReact = lower.includes("react") || lower.includes("tsx") || lower.includes("jsx");
  const hasPython = lower.includes("fastapi") || lower.includes("flask") || lower.includes("uvicorn") || lower.includes("django");
  const hasNode = lower.includes("express") || lower.includes("nest") || lower.includes("koa") || lower.includes("router.");
  if (hasElectron && hasReact && hasPython) {
    return "Electron desktop application with React renderer and Python backend";
  }
  if (hasElectron && hasReact) {
    return "Electron desktop application with React renderer";
  }
  if (hasPython && hasReact) {
    return "Polyglot application with React frontend and Python backend";
  }
  if (hasPython && hasNode) {
    return "Polyglot application with Python backend and JavaScript/TypeScript frontend";
  }
  if (hasPython) {
    return "Python application or API service";
  }
  if (hasNode) {
    return "JavaScript/TypeScript application or API service";
  }
  if (hasReact) {
    return "React application";
  }
  return "Source code application";
}

function detectTechnologyStack(samples: FileSample[]): string[] {
  const stack = new Set<string>();
  const joined = samples.map((sample) => `${sample.relativePath}\n${sample.content.slice(0, 4000)}`).join("\n").toLowerCase();
  if (joined.includes("electron")) stack.add("Electron");
  if (joined.includes("react")) stack.add("React");
  if (joined.includes("fastapi")) stack.add("FastAPI");
  if (joined.includes("flask")) stack.add("Flask");
  if (joined.includes("uvicorn")) stack.add("Uvicorn");
  if (joined.includes("typescript") || samples.some((sample) => sample.language === "typescript")) stack.add("TypeScript");
  if (samples.some((sample) => sample.language === "javascript")) stack.add("JavaScript");
  if (samples.some((sample) => sample.language === "python")) stack.add("Python");
  if (samples.some((sample) => sample.language === "go")) stack.add("Go");
  if (samples.some((sample) => sample.language === "java")) stack.add("Java");
  if (samples.some((sample) => sample.language === "csharp")) stack.add("C#");
  if (joined.includes("pdfkit")) stack.add("PDF generation");
  if (joined.includes("sqlite")) stack.add("SQLite");
  if (joined.includes("postgres")) stack.add("PostgreSQL");
  if (joined.includes("ollama")) stack.add("Ollama");
  return [...stack];
}

function detectExternalIntegrations(samples: FileSample[]): string[] {
  const integrations: string[] = [];
  const joined = samples.map((sample) => sample.content).join("\n").toLowerCase();
  const candidates: Array<[string, RegExp]> = [
    ["Filesystem", /\b(fs\.promises|path\.|os\.path|readfile|writefile|readdir)\b/i],
    ["Local report/export folder", /\bexport(dir|path)|report(history|export)|pdfkit\b/i],
    ["Electron shell/dialogs", /\b(shell\.|dialog\.|ipcmain\b)/i],
    ["SQLite", /\bsqlite\b/i],
    ["PostgreSQL", /\bpostgres\b/i],
    ["Ollama", /\bollama\b/i],
    ["SMTP/email", /\bsmtp\b|\bnodemailer\b/i],
    ["Git repository metadata", /\bgit\b|\bscm\b|\bdiff\b/i],
  ];
  for (const [label, regex] of candidates) {
    if (regex.test(joined)) {
      integrations.push(label);
    }
  }
  return uniqueValues(integrations);
}

function detectMainComponents(samples: FileSample[]): string[] {
  const components = new Set<string>();
  for (const sample of samples) {
    const rel = sample.relativePath.toLowerCase();
    const content = sample.content.toLowerCase();
    if (rel.includes("frontend/src/app.tsx") || rel.includes("renderer") || content.includes("react")) {
      components.add("Frontend renderer");
    }
    if (rel.includes("electron/main.ts") || content.includes("ipcmain.handle")) {
      components.add("Electron main process");
    }
    if (rel.includes("electron/preload.ts") || content.includes("contextbridge.exposeinmainworld")) {
      components.add("Preload bridge");
    }
    if (rel.includes("backend/exportservice.ts") || rel.includes("reporting/export") || content.includes("exportreport(")) {
      components.add("Report exporter");
    }
    if (rel.includes("scanner/engine") || rel.includes("scanengine") || content.includes("progress_callback")) {
      components.add("Analysis engine");
    }
    if (rel.includes("database/store") || content.includes("class scanstore")) {
      components.add("Local scan store");
    }
    if (rel.includes("toolaccessauth") || rel.includes("toolmanager")) {
      components.add("Analyzer access control");
    }
    if (rel.includes("web/app.py") || content.includes("fastapi(") || content.includes("@app.")) {
      components.add("Python API backend");
    }
  }
  return [...components];
}

function findLineMatches(
  samples: FileSample[],
  matcher: (line: string) => { name: string; type: string; exposure: "Public" | "Authenticated" | "Internal"; details: string } | null,
): ThreatModelEntryPoint[] {
  const entries: ThreatModelEntryPoint[] = [];
  const seen = new Set<string>();
  for (const sample of samples) {
    const lines = sample.content.split(/\r?\n/);
    lines.forEach((line, index) => {
      const match = matcher(line);
      if (!match) {
        return;
      }
      const key = `${sample.relativePath}:${index + 1}:${match.name}`;
      if (seen.has(key)) {
        return;
      }
      seen.add(key);
      entries.push({
        name: match.name,
        type: match.type,
        file: sample.relativePath,
        line: index + 1,
        exposure: match.exposure,
        details: match.details,
      });
    });
  }
  return entries;
}

function extractEntryPoints(samples: FileSample[]): ThreatModelEntryPoint[] {
  const routes = findLineMatches(samples, (line) => {
    const fastApi = /^\s*@\s*(?:app|router)\.(get|post|put|delete|patch)\(\s*["'`]([^"'`]+)["'`]/i.exec(line);
    if (fastApi) {
      const method = fastApi[1].toUpperCase();
      const route = fastApi[2];
      const name = `${method} ${route}`;
      return {
        name,
        type: "HTTP route",
        exposure: route.includes("admin") || route.includes("tools") || route.includes("export") ? "Authenticated" : "Public",
        details: `FastAPI route decorator exposes ${method} ${route}.`,
      };
    }
    const express = /^\s*(?:app|router)\.(get|post|put|delete|patch|use)\(\s*["'`]([^"'`]+)["'`]/i.exec(line);
    if (express) {
      const method = express[1].toUpperCase();
      const route = express[2];
      return {
        name: `${method} ${route}`,
        type: "HTTP route",
        exposure: route.includes("admin") || route.includes("export") || route.includes("auth") ? "Authenticated" : "Public",
        details: `Express-style route handler exposes ${method} ${route}.`,
      };
    }
    const ipc = /\bipcMain\.(handle|on)\(\s*["'`]([^"'`]+)["'`]/i.exec(line);
    if (ipc) {
      const channel = ipc[2];
      return {
        name: channel,
        type: "Desktop IPC channel",
        exposure: "Internal",
        details: `Electron IPC channel ${channel} can be invoked by the renderer process.`,
      };
    }
    const dialog = /\bshowOpenDialog(?:Sync)?\(|\bpickProjectFolder\(|\bopenFile\b|\bopenDirectory\b/i.exec(line);
    if (dialog) {
      return {
        name: "File or folder picker",
        type: "Local file selection",
        exposure: "Internal",
        details: "Local file or folder selection opens a trust boundary from user input into the analysis backend.",
      };
    }
    return null;
  });

  const authLike = findLineMatches(samples, (line) => {
    if (!/\b(auth|login|logout|session|token|verify|password|mfa|otp)\b/i.test(line)) {
      return null;
    }
    const route = /["'`]([^"'`]*(?:auth|login|logout|session|token|verify)[^"'`]*)["'`]/i.exec(line);
    const name = route ? route[1] : line.trim().slice(0, 90);
    return {
      name,
      type: "Authentication or access-control logic",
      exposure: /admin|auth|token|session/i.test(line) ? "Authenticated" : "Internal",
      details: "Authentication, session, or authorization logic is present in the code path.",
    };
  });

  return [...routes, ...authLike].sort((left, right) => left.file.localeCompare(right.file) || left.line - right.line);
}

function buildTrustBoundaries(entryPoints: ThreatModelEntryPoint[], components: string[], externalIntegrations: string[]): ThreatModelTrustBoundary[] {
  const boundaries: ThreatModelTrustBoundary[] = [];
  if (components.includes("Frontend renderer") || components.includes("Electron main process") || components.includes("Preload bridge")) {
    boundaries.push({
      from: "User / Browser UI",
      to: "Application renderer",
      data: ["codebase path", "scan request", "threat-model request"],
      description: "User-driven actions cross from the UI into renderer logic.",
    });
  }
  if (components.includes("Electron main process") || components.includes("Python API backend") || components.includes("Analysis engine")) {
    boundaries.push({
      from: "Renderer / IPC",
      to: "Backend services",
      data: ["IPC channels", "route handlers", "analysis requests"],
      description: "Privileged application logic receives user-controlled requests from the renderer or HTTP layer.",
    });
  }
  if (components.includes("Local scan store") || components.includes("Report exporter")) {
    boundaries.push({
      from: "Backend services",
      to: "Local storage",
      data: ["scan records", "threat-model artifacts", "exported reports"],
      description: "Analysis results are persisted locally for later review and export.",
    });
  }
  if (externalIntegrations.length > 0) {
    boundaries.push({
      from: "Backend services",
      to: "External integrations",
      data: externalIntegrations,
      description: "Optional integrations introduce additional trust boundaries that should be validated separately.",
    });
  }
  if (entryPoints.some((item) => item.type.includes("Authentication"))) {
    boundaries.push({
      from: "Unauthenticated / authenticated caller",
      to: "Access-controlled operations",
      data: ["tokens", "sessions", "role claims"],
      description: "Identity and authorization decisions must be enforced before privileged operations execute.",
    });
  }
  return boundaries;
}

function buildDataFlows(components: string[], entryPoints: ThreatModelEntryPoint[]): ThreatModelDataFlow[] {
  const flows: ThreatModelDataFlow[] = [];
  if (entryPoints.length > 0) {
    flows.push({
      source: "User-selected codebase path",
      destination: "Threat model analyzer",
      data: "filesystem path and source tree",
      description: "The user chooses a file or folder and the threat model engine traverses source code from that path only.",
    });
  }
  if (components.includes("Frontend renderer") && components.includes("Electron main process")) {
    flows.push({
      source: "Frontend renderer",
      destination: "Electron main process",
      data: "IPC request payloads",
      description: "Renderer requests are passed through a controlled IPC boundary into the privileged main process.",
    });
  }
  if (components.includes("Electron main process") && components.includes("Analysis engine")) {
    flows.push({
      source: "Electron main process",
      destination: "Analysis engine",
      data: "path, analysis options, and runtime context",
      description: "The main process invokes the code-only threat modeling engine for the selected target.",
    });
  }
  if (components.includes("Analysis engine") && components.includes("Report exporter")) {
    flows.push({
      source: "Analysis engine",
      destination: "Threat model JSON / Mermaid report",
      data: "system overview, entry points, boundaries, threats",
      description: "The engine serializes STRIDE findings into a consumable report and Mermaid diagram.",
    });
  }
  return flows;
}

function buildThreats(
  samples: FileSample[],
  entryPoints: ThreatModelEntryPoint[],
  components: string[],
  externalIntegrations: string[],
): ThreatModelThreat[] {
  const threats: ThreatModelThreat[] = [];
  const joined = samples.map((sample) => sample.content).join("\n").toLowerCase();
  const hasPrivilegedHandlers = entryPoints.some((item) => /scan:|tools:|reset|export|audit|threat:model/i.test(item.name));
  const hasRecursiveTraversal = joined.includes("readdir") || joined.includes("rglob") || joined.includes("recursive");
  const hasExports = joined.includes("export") || joined.includes("writefile") || joined.includes("pdfkit");
  const hasAuth = joined.includes("token") || joined.includes("session") || joined.includes("auth") || joined.includes("otp") || joined.includes("mfa");
  const hasLogs = joined.includes("audit") || joined.includes("log");
  const hasSecrets = joined.includes("secret") || joined.includes("credential") || joined.includes("password") || joined.includes("api_key");

  if (hasAuth || hasPrivilegedHandlers) {
    threats.push({
      title: "Renderer or caller can influence privileged operations",
      component: components.includes("Electron main process") ? "Electron main process IPC" : "Backend route handling",
      stride_category: "Spoofing",
      description: "Privilege-sensitive actions are exposed through callable handlers or endpoints that must not trust caller-supplied role or identity data.",
      abuse_case: "Attacker forges a higher-privilege request or replays an old session claim to reach an operation that should only be available to privileged users.",
      impact: "High",
      likelihood: "Medium",
      exposure: hasPrivilegedHandlers ? "Authenticated" : "Public",
      mitigation: "Enforce authorization server-side for every privileged handler, derive identity from verified session state, and reject caller-supplied role claims.",
    });
  }

  if (hasExports || externalIntegrations.includes("Filesystem") || externalIntegrations.includes("Local report/export folder")) {
    threats.push({
      title: "Path-controlled exports can tamper with local artifacts",
      component: "Report exporter / filesystem writer",
      stride_category: "Tampering",
      description: "Export and artifact-writing paths are influenced by repository or user input, so outputs must be normalized and confined to approved directories.",
      abuse_case: "Attacker crafts a target path or export name that overwrites a predictable local file or places a report where another process reads it as trusted input.",
      impact: "High",
      likelihood: "Medium",
      exposure: "Authenticated",
      mitigation: "Canonicalize output paths, enforce a fixed export root, reject traversal segments, and ensure report names are sanitized before writing.",
    });
  }

  if (hasLogs || joined.includes("history") || joined.includes("audit")) {
    threats.push({
      title: "Local audit trail can be cleared or bypassed",
      component: "Audit logging and history management",
      stride_category: "Repudiation",
      description: "If audit logs and history are stored locally without integrity protection, malicious users can erase traces of sensitive operations.",
      abuse_case: "User performs a high-risk action and then clears local history or resets the cache so there is no trustworthy evidence left behind.",
      impact: "Medium",
      likelihood: "Medium",
      exposure: "Authenticated",
      mitigation: "Use append-only audit logging, add integrity metadata or signing, and keep audit retention separate from regular user-managed history cleanup.",
    });
  }

  if (hasSecrets || hasExports || joined.includes("snippet") || joined.includes("evidence")) {
    threats.push({
      title: "Reports can disclose code, paths, and secrets",
      component: "Threat model / report rendering pipeline",
      stride_category: "Information Disclosure",
      description: "Rendered reports, code evidence, and exported artifacts may expose source lines, paths, tokens, or other sensitive context.",
      abuse_case: "A user opens or exports a report and gains access to nearby code snippets, file paths, or secret material that should be redacted for their role.",
      impact: "High",
      likelihood: "High",
      exposure: "Authenticated",
      mitigation: "Apply role-based redaction consistently, hide sensitive evidence by default for executive views, and avoid exporting secrets or raw credential material.",
    });
  }

  if (hasRecursiveTraversal) {
    threats.push({
      title: "Large repository traversal can exhaust local resources",
      component: "Source discovery and analysis engine",
      stride_category: "Denial of Service",
      description: "Recursive file discovery and deep analysis can become expensive on large repositories or on trees with many generated files.",
      abuse_case: "Attacker selects a very large tree or a path full of nested generated files and forces the analyzer to spend excessive CPU and memory.",
      impact: "Medium",
      likelihood: "High",
      exposure: "Public",
      mitigation: "Cap file counts, skip generated directories, bound per-file size, and use worker/time limits for discovery, parsing, and rendering.",
    });
  }

  if (components.includes("Electron main process") || components.includes("Analysis engine") || hasPrivilegedHandlers) {
    threats.push({
      title: "Privileged desktop handlers can elevate access if authorization drifts",
      component: "Electron main process / backend service",
      stride_category: "Elevation of Privilege",
      description: "Privileged application handlers should never rely on UI state alone for authorization because renderer code can be manipulated locally.",
      abuse_case: "An attacker crafts IPC payloads or local state mutations to invoke operations that were intended only for administrators or tool owners.",
      impact: "High",
      likelihood: "Medium",
      exposure: "Internal",
      mitigation: "Check authorization in the privileged layer, keep renderer claims advisory only, and restrict sensitive operations by validated session and role.",
    });
  }

  return threats;
}

function buildMermaidDiagram(report: ThreatModelReport): string {
  const body = [
    "flowchart TD",
    "  subgraph TB1[Trust boundary: User interface]",
    "    user([User]) -->|select codebase| ui[Frontend renderer]",
    "  end",
    "  subgraph TB2[Trust boundary: privileged analysis]",
    "    ui -->|IPC request| bridge[Electron main process]",
    "    bridge -->|path + options| engine[Threat model analyzer]",
    "    engine -->|read source code| repo[(Source code repository)]",
    "    engine -->|write JSON / HTML / Mermaid| store[(Threat model artifacts)]",
    "  end",
    "  bridge -->|rendered model| ui",
  ];
  return body.join("\n");
}

function escapeHtml(input: string): string {
  return String(input || "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function renderThreatHtml(report: ThreatModelReport): string {
  const overviewList = report.system_overview.main_components.map((item) => `<li>${escapeHtml(item)}</li>`).join("");
  const integrationsList = report.system_overview.external_integrations.length
    ? report.system_overview.external_integrations.map((item) => `<li>${escapeHtml(item)}</li>`).join("")
    : "<li>No external integrations detected.</li>";
  const stackList = report.system_overview.technology_stack.map((item) => `<li>${escapeHtml(item)}</li>`).join("");
  const entryRows = report.entry_points
    .map(
      (item) => `<tr>
        <td>${escapeHtml(item.name)}</td>
        <td>${escapeHtml(item.type)}</td>
        <td>${escapeHtml(item.exposure)}</td>
        <td>${escapeHtml(item.file)}:${Number(item.line || 0)}</td>
        <td>${escapeHtml(item.details)}</td>
      </tr>`,
    )
    .join("");
  const boundaryRows = report.trust_boundaries
    .map(
      (item) => `<tr>
        <td>${escapeHtml(item.from)}</td>
        <td>${escapeHtml(item.to)}</td>
        <td>${escapeHtml(item.data.join(", "))}</td>
        <td>${escapeHtml(item.description)}</td>
      </tr>`,
    )
    .join("");
  const flowRows = report.data_flows
    .map(
      (item) => `<tr>
        <td>${escapeHtml(item.source)}</td>
        <td>${escapeHtml(item.destination)}</td>
        <td>${escapeHtml(item.data)}</td>
        <td>${escapeHtml(item.description)}</td>
      </tr>`,
    )
    .join("");
  const threatRows = report.threats
    .map(
      (item) => `<tr>
        <td><strong>${escapeHtml(item.title)}</strong></td>
        <td>${escapeHtml(item.component)}</td>
        <td>${escapeHtml(item.stride_category)}</td>
        <td>${escapeHtml(item.impact)}</td>
        <td>${escapeHtml(item.likelihood)}</td>
        <td>${escapeHtml(item.exposure)}</td>
        <td>${escapeHtml(item.abuse_case)}</td>
        <td>${escapeHtml(item.mitigation)}</td>
      </tr>`,
    )
    .join("");

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>CodeSentinelX Threat Model</title>
  <style>
    body { margin:0; background:#08111c; color:#e8eef6; font-family:Segoe UI, Arial, sans-serif; }
    .shell { max-width: 1400px; margin: 0 auto; padding: 24px; }
    .hero { background:#0d1726; border:1px solid rgba(120,168,205,.22); border-radius:18px; padding:20px; margin-bottom:16px; }
    .meta { display:flex; gap:12px; flex-wrap:wrap; margin-top:10px; }
    .pill { border:1px solid rgba(120,168,205,.2); border-radius:999px; padding:8px 12px; background:rgba(255,255,255,.03); }
    .grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(260px,1fr)); gap:12px; margin:16px 0; }
    .card { background:#0b1522; border:1px solid rgba(120,168,205,.18); border-radius:16px; padding:16px; }
    h1,h2,h3 { margin:0 0 10px; }
    table { width:100%; border-collapse:collapse; }
    th,td { border:1px solid rgba(120,168,205,.16); padding:8px 10px; vertical-align:top; }
    th { background:rgba(255,255,255,.04); text-align:left; }
    pre { white-space:pre-wrap; word-break:break-word; background:#06101a; border:1px solid rgba(120,168,205,.16); border-radius:12px; padding:14px; overflow:auto; }
    ul { margin: 0 0 0 18px; }
    .muted { color:#9ab0c8; }
    .two-col { display:grid; grid-template-columns:1.1fr .9fr; gap:12px; }
    .code-box { min-height:220px; }
  </style>
</head>
<body>
  <main class="shell">
    <section class="hero">
      <h1>CodeSentinelX Threat Model</h1>
      <p class="muted">STRIDE analysis generated from code only. This workflow is separate from the canonical scan pipeline.</p>
      <div class="meta">
        <div class="pill"><strong>Target:</strong> ${escapeHtml(report.target_path)}</div>
        <div class="pill"><strong>Type:</strong> ${escapeHtml(report.target_type)}</div>
        <div class="pill"><strong>Generated:</strong> ${escapeHtml(report.generated_at)}</div>
        <div class="pill"><strong>Source files analyzed:</strong> ${report.summary.source_files_analyzed}</div>
        <div class="pill"><strong>Entry points:</strong> ${report.summary.entry_points}</div>
        <div class="pill"><strong>Threats:</strong> ${report.summary.threats}</div>
      </div>
    </section>

    <section class="grid">
      <article class="card">
        <h2>System Overview</h2>
        <p><strong>Application Type:</strong> ${escapeHtml(report.system_overview.application_type)}</p>
        <h3>Main Components</h3>
        <ul>${overviewList || "<li>No components detected.</li>"}</ul>
        <h3>External Integrations</h3>
        <ul>${integrationsList}</ul>
        <h3>Technology Stack</h3>
        <ul>${stackList || "<li>No stack detected.</li>"}</ul>
      </article>
      <article class="card">
        <h2>Diagram</h2>
        <p class="muted">Mermaid flowchart for trust boundaries and high-level data movement.</p>
        <pre>${escapeHtml(report.diagram)}</pre>
      </article>
    </section>

    <section class="card">
      <h2>Entry Points</h2>
      <table>
        <thead><tr><th>Name</th><th>Type</th><th>Exposure</th><th>Location</th><th>Details</th></tr></thead>
        <tbody>${entryRows || "<tr><td colspan='5'>No entry points detected.</td></tr>"}</tbody>
      </table>
    </section>

    <section class="card">
      <h2>Trust Boundaries</h2>
      <table>
        <thead><tr><th>From</th><th>To</th><th>Data</th><th>Description</th></tr></thead>
        <tbody>${boundaryRows || "<tr><td colspan='4'>No trust boundaries detected.</td></tr>"}</tbody>
      </table>
    </section>

    <section class="card">
      <h2>Data Flows</h2>
      <table>
        <thead><tr><th>Source</th><th>Destination</th><th>Data</th><th>Description</th></tr></thead>
        <tbody>${flowRows || "<tr><td colspan='4'>No data flows detected.</td></tr>"}</tbody>
      </table>
    </section>

    <section class="card">
      <h2>Threats</h2>
      <table>
        <thead><tr><th>Title</th><th>Component</th><th>STRIDE</th><th>Impact</th><th>Likelihood</th><th>Exposure</th><th>Abuse Case</th><th>Mitigation</th></tr></thead>
        <tbody>${threatRows || "<tr><td colspan='8'>No threats detected from the available source code.</td></tr>"}</tbody>
      </table>
    </section>

    <section class="two-col">
      <article class="card code-box">
        <h2>JSON</h2>
        <pre>${escapeHtml(JSON.stringify(report, null, 2))}</pre>
      </article>
      <article class="card code-box">
        <h2>Mermaid</h2>
        <pre>${escapeHtml(report.diagram)}</pre>
      </article>
    </section>
  </main>
</body>
</html>`;
}

export class ThreatModelService {
  constructor(private readonly outputDir: string) {}

  async createThreatModel(request: ThreatModelRequest): Promise<ThreatModelResult> {
    const resolved = path.resolve(request.projectPath);
    const stat = await fs.promises.stat(resolved).catch(() => null);
    if (!stat || (!stat.isDirectory() && !stat.isFile())) {
      throw new Error("Provided path does not exist or is not a file or directory.");
    }

    const files = await collectFiles(resolved);
    const samples: FileSample[] = [];
    for (const filePath of files) {
      const content = await safeReadText(filePath);
      if (!content.trim()) {
        continue;
      }
      samples.push({
        filePath,
        relativePath: toPosixPath(path.relative(resolved, filePath) || path.basename(filePath)),
        content,
        language: fileLanguage(filePath),
      });
    }

    const entryPoints = extractEntryPoints(samples);
    const mainComponents = detectMainComponents(samples);
    const externalIntegrations = detectExternalIntegrations(samples);
    const dataFlows = buildDataFlows(mainComponents, entryPoints);
    const threats = buildThreats(samples, entryPoints, mainComponents, externalIntegrations);
    const trustBoundaries = buildTrustBoundaries(entryPoints, mainComponents, externalIntegrations);
    const report: ThreatModelReport = {
      schema_version: "codesentinelx.threat_model.v1",
      target_path: resolved,
      target_type: stat.isFile() ? "file" : "folder",
      generated_at: new Date().toISOString(),
      system_overview: {
        application_type: detectApplicationType(samples),
        main_components: mainComponents,
        external_integrations: externalIntegrations,
        technology_stack: detectTechnologyStack(samples),
      },
      entry_points: entryPoints,
      trust_boundaries: trustBoundaries,
      data_flows: dataFlows,
      threats,
      diagram: "",
      summary: {
        source_files_analyzed: samples.length,
        entry_points: entryPoints.length,
        threats: threats.length,
      },
    };

    report.diagram = buildMermaidDiagram(report);

    const safeName = path
      .basename(resolved)
      .replace(/\.[^.]+$/, "")
      .replace(/[^A-Za-z0-9._-]+/g, "_")
      .replace(/^_+|_+$/g, "") || "threat_model";
    const timestamp = report.generated_at.replace(/[:.]/g, "-");
    const targetDir = path.join(this.outputDir, "threat-models", safeName);
    await fs.promises.mkdir(targetDir, { recursive: true });
    const jsonPath = path.join(targetDir, `${timestamp}_threat_model.json`);
    const mermaidPath = path.join(targetDir, `${timestamp}_threat_model.mmd`);
    const htmlPath = path.join(targetDir, `${timestamp}_threat_model.html`);
    await fs.promises.writeFile(jsonPath, JSON.stringify(report, null, 2), "utf-8");
    await fs.promises.writeFile(mermaidPath, `${report.diagram}\n`, "utf-8");
    await fs.promises.writeFile(htmlPath, renderThreatHtml(report), "utf-8");

    return {
      report,
      jsonPath,
      htmlPath,
      mermaidPath,
    };
  }
}
