import fs from "node:fs";
import path from "node:path";

import {
  ThreatModelAsset,
  ThreatModelDataFlow,
  ThreatModelEntryPoint,
  ThreatModelReport,
  ThreatModelRequest,
  ThreatModelResult,
  ThreatModelCodeMapping,
  ThreatModelFramework,
  ThreatModelSecurityObjective,
  ThreatModelTraceabilityItem,
  ThreatModelValidationPlanItem,
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

const THREAT_MODEL_FRAMEWORKS: ThreatModelFramework[] = ["STRIDE", "DREAD", "OWASP", "PASTA"];

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

function escapeRegExp(input: string): string {
  return String(input || "").replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function collectEvidence(
  samples: FileSample[],
  patterns: RegExp[],
  maxItems = 3,
): Array<{ file: string; line: number; excerpt: string }> {
  const evidence: Array<{ file: string; line: number; excerpt: string }> = [];
  const seen = new Set<string>();
  for (const sample of samples) {
    const lines = sample.content.split(/\r?\n/);
    for (let index = 0; index < lines.length; index += 1) {
      const line = lines[index];
      if (!patterns.some((pattern) => pattern.test(line))) {
        continue;
      }
      const excerpt = line.trim().slice(0, 220);
      const key = `${sample.relativePath}:${index + 1}:${excerpt}`;
      if (seen.has(key)) {
        continue;
      }
      seen.add(key);
      evidence.push({
        file: sample.relativePath,
        line: index + 1,
        excerpt,
      });
      if (evidence.length >= maxItems) {
        return evidence;
      }
    }
  }
  return evidence;
}

function uniqueValues(items: string[]): string[] {
  return [...new Set(items.map((item) => item.trim()).filter(Boolean))];
}

function normalizeThreatModelFramework(input: unknown): ThreatModelFramework {
  const candidate = String(input || "").trim().toUpperCase();
  return (THREAT_MODEL_FRAMEWORKS as string[]).includes(candidate) ? (candidate as ThreatModelFramework) : "STRIDE";
}

function threatModelFrameworkLabel(framework: ThreatModelFramework): string {
  switch (framework) {
    case "DREAD":
      return "DREAD";
    case "OWASP":
      return "OWASP";
    case "PASTA":
      return "PASTA";
    case "STRIDE":
    default:
      return "STRIDE";
  }
}

function mapStrideThreatToOwasp(strideCategory: ThreatModelThreat["stride_category"], threat: Pick<ThreatModelThreat, "title" | "component" | "description">): string {
  const text = `${threat.title} ${threat.component} ${threat.description}`.toLowerCase();
  if (strideCategory === "Spoofing" || strideCategory === "Elevation of Privilege") {
    return "A01:2021 - Broken Access Control";
  }
  if (strideCategory === "Repudiation") {
    return "A09:2021 - Security Logging and Monitoring Failures";
  }
  if (strideCategory === "Information Disclosure") {
    return text.includes("secret") || text.includes("credential") || text.includes("token")
      ? "A02:2021 - Cryptographic Failures"
      : "A01:2021 - Broken Access Control";
  }
  if (strideCategory === "Denial of Service") {
    return "A04:2021 - Insecure Design";
  }
  if (text.includes("export") || text.includes("write") || text.includes("tamper")) {
    return "A08:2021 - Software and Data Integrity Failures";
  }
  if (text.includes("login") || text.includes("session") || text.includes("auth")) {
    return "A07:2021 - Identification and Authentication Failures";
  }
  return "A05:2021 - Security Misconfiguration";
}

function mapStrideThreatToPastaStage(threat: Pick<ThreatModelThreat, "title" | "component" | "description">): string {
  const text = `${threat.title} ${threat.component} ${threat.description}`.toLowerCase();
  if (text.includes("privilege") || text.includes("auth") || text.includes("session")) {
    return "Stage 6 - Attack Modeling";
  }
  if (text.includes("export") || text.includes("write") || text.includes("tamper")) {
    return "Stage 5 - Vulnerability Analysis";
  }
  if (text.includes("audit") || text.includes("log") || text.includes("history")) {
    return "Stage 4 - Threat Analysis";
  }
  if (text.includes("secret") || text.includes("token") || text.includes("credential")) {
    return "Stage 3 - Application Decomposition";
  }
  return "Stage 6 - Attack Modeling";
}

function computeDreadBreakdown(
  threat: Pick<ThreatModelThreat, "impact" | "likelihood" | "exposure" | "evidence" | "title" | "component" | "description">,
): NonNullable<ThreatModelThreat["dread_breakdown"]> {
  const damage = threat.impact === "High" ? 9 : threat.impact === "Medium" ? 6 : 3;
  const reproducibility = threat.likelihood === "High" ? 8 : threat.likelihood === "Medium" ? 5 : 2;
  const exploitability = threat.exposure === "Public" ? 9 : threat.exposure === "Authenticated" ? 6 : 3;
  const affectedUsers = threat.exposure === "Public" ? 9 : threat.exposure === "Authenticated" ? 5 : 2;
  const evidenceCount = Array.isArray(threat.evidence) ? threat.evidence.length : 0;
  const discoverability = Math.min(10, 4 + evidenceCount * 2 + (String(threat.title || threat.component || threat.description).length > 40 ? 1 : 0));
  return {
    damage,
    reproducibility,
    exploitability,
    affected_users: affectedUsers,
    discoverability,
  };
}

function computeFrameworkScore(framework: ThreatModelFramework, threat: ThreatModelThreat): number {
  if (framework === "DREAD") {
    const breakdown = computeDreadBreakdown(threat);
    const average = (breakdown.damage + breakdown.reproducibility + breakdown.exploitability + breakdown.affected_users + breakdown.discoverability) / 5;
    return Number(average.toFixed(1));
  }
  return estimateThreatScore(threat.impact, threat.likelihood, threat.exposure);
}

function adaptThreatForFramework(threat: ThreatModelThreat, framework: ThreatModelFramework): ThreatModelThreat {
  const frameworkCategory =
    framework === "OWASP"
      ? mapStrideThreatToOwasp(threat.stride_category, threat)
      : framework === "PASTA"
        ? mapStrideThreatToPastaStage(threat)
        : threat.stride_category;
  const adapted: ThreatModelThreat = {
    ...threat,
    framework_category: frameworkCategory,
    framework_notes:
      framework === "STRIDE"
        ? "Direct STRIDE mapping from code evidence."
        : framework === "OWASP"
          ? "OWASP Top 10 oriented model derived from the same code evidence."
          : framework === "DREAD"
            ? "DREAD scoring applied to the same evidence-backed threat."
            : "PASTA stage-aligned view derived from the same evidence-backed threat.",
    owasp_category: framework === "OWASP" ? frameworkCategory : threat.owasp_category,
    pasta_stage: framework === "PASTA" ? frameworkCategory : threat.pasta_stage,
    dread_breakdown: framework === "DREAD" ? computeDreadBreakdown(threat) : threat.dread_breakdown,
    risk_score: computeFrameworkScore(framework, threat),
    risk_level:
      computeFrameworkScore(framework, threat) >= 8
        ? "Critical"
        : computeFrameworkScore(framework, threat) >= 6.5
          ? "High"
          : computeFrameworkScore(framework, threat) >= 4
            ? "Medium"
            : "Low",
  };
  return adapted;
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
      components.add("Application UI");
    }
    if (rel.includes("electron/main.ts") || content.includes("ipcmain.handle")) {
      components.add("Desktop service");
    }
    if (rel.includes("electron/preload.ts") || content.includes("contextbridge.exposeinmainworld")) {
      components.add("Security bridge");
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
      components.add("Analysis governance");
    }
    if (rel.includes("web/app.py") || content.includes("fastapi(") || content.includes("@app.")) {
      components.add("Python service backend");
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
  if (components.includes("Application UI") || components.includes("Desktop service") || components.includes("Security bridge")) {
    boundaries.push({
      from: "User interface",
      to: "Application UI",
      data: ["codebase path", "scan request", "threat-model request"],
      description: "User-driven actions cross from the interface into application logic.",
    });
  }
  if (components.includes("Desktop service") || components.includes("Python service backend") || components.includes("Analysis engine")) {
    boundaries.push({
      from: "Application UI / IPC",
      to: "Backend services",
      data: ["IPC channels", "route handlers", "analysis requests"],
      description: "Privileged application logic receives user-controlled requests from the UI or HTTP layer.",
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
      source: "Target codebase path",
      destination: "Analysis engine",
      data: "filesystem path and source tree",
      description: "The user chooses a file or folder and the threat model engine traverses source code from that path only.",
    });
  }
  if (components.includes("Application UI") && components.includes("Desktop service")) {
    flows.push({
      source: "Application UI",
      destination: "Desktop service",
      data: "IPC request payloads",
      description: "Renderer requests are passed through a controlled IPC boundary into the privileged main process.",
    });
  }
  if (components.includes("Desktop service") && components.includes("Analysis engine")) {
    flows.push({
      source: "Desktop service",
      destination: "Analysis engine",
      data: "path, analysis options, and runtime context",
      description: "The main process invokes the code-only threat modeling engine for the selected target.",
    });
  }
  if (components.includes("Analysis engine") && components.includes("Report exporter")) {
    flows.push({
      source: "Analysis engine",
      destination: "Threat model report artifacts",
      data: "system overview, entry points, boundaries, threats",
      description: "The engine serializes STRIDE findings into a consumable report and Mermaid diagram.",
    });
  }
  return flows;
}

function estimateThreatScore(
  impact: ThreatModelThreat["impact"],
  likelihood: ThreatModelThreat["likelihood"],
  exposure: ThreatModelThreat["exposure"],
): number {
  const impactWeight: Record<ThreatModelThreat["impact"], number> = { High: 4, Medium: 3, Low: 2 };
  const likelihoodWeight: Record<ThreatModelThreat["likelihood"], number> = { High: 4, Medium: 3, Low: 1 };
  const exposureWeight: Record<ThreatModelThreat["exposure"], number> = { Public: 2, Authenticated: 1, Internal: 0 };
  return impactWeight[impact] + likelihoodWeight[likelihood] + exposureWeight[exposure];
}

function scoreToLevel(score: number): NonNullable<ThreatModelThreat["risk_level"]> {
  if (score >= 9) {
    return "Critical";
  }
  if (score >= 7) {
    return "High";
  }
  if (score >= 5) {
    return "Medium";
  }
  return "Low";
}

function buildAssets(
  samples: FileSample[],
  entryPoints: ThreatModelEntryPoint[],
  components: string[],
  externalIntegrations: string[],
): ThreatModelAsset[] {
  const assets: ThreatModelAsset[] = [];
  const seen = new Set<string>();
  const pushAsset = (asset: ThreatModelAsset) => {
    const key = `${asset.category}:${asset.name}:${asset.location}`;
    if (seen.has(key)) {
      return;
    }
    seen.add(key);
    assets.push(asset);
  };
  const repoEvidence = samples
    .slice(0, 3)
    .flatMap((sample) => {
      const firstLine = sample.content.split(/\r?\n/).find((line) => line.trim());
      return firstLine
        ? [
            {
              file: sample.relativePath,
              line: 1,
              excerpt: firstLine.trim().slice(0, 220),
            },
          ]
        : [];
    })
    .slice(0, 3);
  const hasAuth = samples.some((sample) => /auth|login|logout|session|token|password|mfa|otp/i.test(sample.content));
  const hasSecrets = samples.some((sample) => /secret|credential|api[_-]?key|private[_-]?key|token/i.test(sample.content));
  const hasExports = samples.some((sample) => /export|report|pdfkit|writefile/i.test(sample.content));
  const hasStore = components.includes("Local scan store") || externalIntegrations.includes("SQLite") || externalIntegrations.includes("PostgreSQL");
  const hasIpc = components.includes("Desktop service") || components.includes("Security bridge");

  pushAsset({
    asset_id: "AS-1",
    name: "Target codebase",
    category: "Repository contents",
    description: "The target codebase itself is the primary asset and must be protected from unauthorized disclosure or modification.",
    location: "Selected codebase path",
    sensitivity: "High",
    evidence: repoEvidence,
  });

  if (entryPoints.some((item) => item.type === "HTTP route")) {
    const evidence = entryPoints
      .filter((item) => item.type === "HTTP route")
      .slice(0, 3)
      .map((item) => ({
        file: item.file,
        line: item.line,
        excerpt: item.name,
      }));
    if (evidence.length > 0) {
    pushAsset({
      asset_id: `AS-${assets.length + 1}`,
      name: "Public and authenticated API routes",
      category: "Application entry points",
      description: "HTTP routes define how callers reach business logic and should be protected with authorization and input validation.",
      location: "Route handlers",
      sensitivity: "High",
      evidence,
    });
    }
  }

  if (hasAuth) {
    const evidence = collectEvidence(samples, [/auth/i, /login/i, /session/i, /token/i, /password/i, /mfa/i, /otp/i]);
    if (evidence.length > 0) {
    pushAsset({
      asset_id: `AS-${assets.length + 1}`,
      name: "Authentication and session state",
      category: "Identity data",
      description: "Session tokens, login state, and auth flows protect privileged operations and must be preserved from spoofing and tampering.",
      location: "Auth/session logic",
      sensitivity: "High",
      evidence,
    });
    }
  }

  if (hasSecrets) {
    const evidence = collectEvidence(samples, [/secret/i, /credential/i, /api[_-]?key/i, /private[_-]?key/i, /token/i, /password/i]);
    if (evidence.length > 0) {
    pushAsset({
      asset_id: `AS-${assets.length + 1}`,
      name: "Secrets and credentials",
      category: "Sensitive material",
      description: "Tokens, API keys, credentials, and related secrets require strong handling and redaction controls.",
      location: "Config, environment, and code references",
      sensitivity: "High",
      evidence,
    });
    }
  }

  if (hasExports) {
    const evidence = collectEvidence(samples, [/export/i, /report/i, /pdfkit/i, /writeFile/i, /resolveOutputPath/i]);
    if (evidence.length > 0) {
    pushAsset({
      asset_id: `AS-${assets.length + 1}`,
      name: "Exported reports and artifacts",
      category: "Generated output",
      description: "Reports, HTML exports, PDFs, and generated artifacts may contain sensitive findings and need controlled access.",
      location: "Report export pipeline",
      sensitivity: "Medium",
      evidence,
    });
    }
  }

  if (hasStore) {
    const evidence = collectEvidence(samples, [/sqlite/i, /postgres/i, /scan store/i, /history/i, /database/i]);
    if (evidence.length > 0) {
    pushAsset({
      asset_id: `AS-${assets.length + 1}`,
      name: "Scan history and local persistence",
      category: "Stored analysis data",
      description: "Local databases or persisted scan history preserve prior findings and should be protected from tampering.",
      location: "Local store or database layer",
      sensitivity: "Medium",
      evidence,
    });
    }
  }

  if (hasIpc) {
    const evidence = collectEvidence(samples, [/ipcMain/i, /contextBridge/i, /postMessage/i, /handle\(/i]);
    if (evidence.length > 0) {
    pushAsset({
      asset_id: `AS-${assets.length + 1}`,
      name: "Renderer-to-main IPC boundary",
      category: "Privilege boundary",
      description: "Desktop IPC requests cross from untrusted renderer state into privileged logic and need strong validation.",
      location: "Electron IPC bridge",
      sensitivity: "High",
      evidence,
    });
    }
  }

  if (externalIntegrations.includes("Filesystem")) {
    const evidence = collectEvidence(samples, [/readdir/i, /writeFile/i, /readFile/i, /path\./i, /resolveOutputPath/i]);
    if (evidence.length > 0) {
    pushAsset({
      asset_id: `AS-${assets.length + 1}`,
      name: "Local filesystem and repository paths",
      category: "Local system resource",
      description: "The filesystem boundary contains source, generated reports, and other local artifacts that should not be traversed freely.",
      location: "Selected path and export roots",
      sensitivity: "Medium",
      evidence,
    });
    }
  }

  if (externalIntegrations.includes("SQLite") || externalIntegrations.includes("PostgreSQL")) {
    const evidence = collectEvidence(samples, [/sqlite/i, /postgres/i, /database/i, /query/i]);
    if (evidence.length > 0) {
    pushAsset({
      asset_id: `AS-${assets.length + 1}`,
      name: "Database records",
      category: "Persistence layer",
      description: "Stored records and scan metadata require integrity and access control because they drive the displayed report state.",
      location: "Database or local persistence",
      sensitivity: "Medium",
      evidence,
    });
    }
  }

  if (externalIntegrations.includes("Ollama")) {
    const evidence = collectEvidence(samples, [/ollama/i, /prompt/i, /remediation/i]);
    if (evidence.length > 0) {
    pushAsset({
      asset_id: `AS-${assets.length + 1}`,
      name: "AI prompt and remediation context",
      category: "AI assistance data",
      description: "Optional local AI workflows may include code snippets and prompt context that should not leak outside the workstation.",
      location: "Local AI provider integration",
      sensitivity: "Medium",
      evidence,
    });
    }
  }

  return assets;
}

function buildSecurityObjectives(assets: ThreatModelAsset[]): ThreatModelSecurityObjective[] {
  return assets.map((asset) => {
    const confidentiality =
      asset.sensitivity === "High"
        ? "Protect strictly from disclosure."
        : asset.sensitivity === "Medium"
          ? "Protect from unnecessary exposure."
          : "Keep accessible to authorized users.";
    const integrity =
      asset.sensitivity === "High"
        ? "Prevent unauthorized modification."
        : asset.sensitivity === "Medium"
          ? "Preserve correctness and provenance."
          : "Preserve content integrity.";
    const availability =
      asset.sensitivity === "High"
        ? "Maintain reliable access for security operations."
        : asset.sensitivity === "Medium"
          ? "Avoid disruption during report generation."
          : "Maintain normal access.";
    return {
      asset_id: asset.asset_id,
      confidentiality,
      integrity,
      availability,
      rationale: `${asset.name} is classified as ${asset.sensitivity} sensitivity in ${asset.category}.`,
    };
  });
}

function buildCodeMappings(threats: ThreatModelThreat[]): ThreatModelCodeMapping[] {
  return threats.flatMap((threat) => {
    const evidence = threat.evidence || [];
    const first = evidence[0];
    if (!first) {
      return [];
    }
    return [
      {
        threat_id: threat.threat_id || threat.title,
        component: threat.component,
        file: first.file,
        line: first.line,
        root_cause: threat.root_cause || first.excerpt,
        cwe: undefined,
      },
    ];
  });
}

function buildValidationPlan(threats: ThreatModelThreat[]): ThreatModelValidationPlanItem[] {
  return threats.map((threat) => {
    const evidence = threat.evidence || [];
    const first = evidence[0];
    const source = first ? `${first.file}:${first.line}` : threat.component;
    return {
      threat_id: threat.threat_id || threat.title,
      check: `Write a regression test for ${threat.title} at ${source}.`,
      expected_verification:
        threat.stride_category === "Spoofing"
          ? "Unauthorized caller identity is rejected by the privileged boundary."
          : threat.stride_category === "Tampering"
            ? "Output paths remain confined and sanitized."
            : threat.stride_category === "Repudiation"
              ? "Audit actions remain traceable after cleanup attempts."
              : threat.stride_category === "Information Disclosure"
                ? "Sensitive code or secret material is redacted from the report."
                : threat.stride_category === "Denial of Service"
                  ? "Traversal and processing stay within bounded limits."
                  : "Privileged calls require validated authorization.",
    };
  });
}

function buildTraceability(threats: ThreatModelThreat[]): ThreatModelTraceabilityItem[] {
  return threats.map((threat) => {
    const evidence = threat.evidence || [];
    const first = evidence[0];
    return {
      threat_id: threat.threat_id || threat.title,
      evidence: first ? `${first.file}:${first.line} - ${first.excerpt}` : "No direct evidence recorded.",
      status: threat.review_status || "Pending reviewer validation",
    };
  });
}

function buildResidualRisk(threats: ThreatModelThreat[]): string[] {
  const pending = threats.filter((threat) => (threat.review_status || "").toLowerCase().includes("pending"));
  if (pending.length === 0) {
    return [];
  }
  return [
    `${pending.length} threat(s) remain pending reviewer validation.`,
    "Residual risk stays tied to direct code evidence until reviewer sign-off is recorded.",
  ];
}

function buildAssumptions(samples: FileSample[], components: string[]): string[] {
  const assumptions: string[] = [];
  if (samples.length > 0) {
    assumptions.push("Threat model scope is limited to the selected source tree and the files discovered during this run.");
  }
  if (components.includes("Desktop service") || components.includes("Application UI")) {
    assumptions.push("Renderer-to-main requests are treated as untrusted until validated in privileged code.");
  }
  if (components.includes("Report exporter")) {
    assumptions.push("Generated artifacts are assumed to be local workstation outputs unless explicitly published elsewhere.");
  }
  return assumptions;
}

function buildThreats(
  samples: FileSample[],
  entryPoints: ThreatModelEntryPoint[],
  components: string[],
  externalIntegrations: string[],
  framework: ThreatModelFramework,
): ThreatModelThreat[] {
  const threats: ThreatModelThreat[] = [];
  const nextId = () => `TM-${threats.length + 1}`;
  const joined = samples.map((sample) => sample.content).join("\n").toLowerCase();
  const hasPrivilegedHandlers = entryPoints.some((item) => /scan:|tools:|reset|export|audit|threat:model/i.test(item.name));
  const hasRecursiveTraversal = joined.includes("readdir") || joined.includes("rglob") || joined.includes("recursive");
  const hasExports = joined.includes("export") || joined.includes("writefile") || joined.includes("pdfkit");
  const hasAuth = joined.includes("token") || joined.includes("session") || joined.includes("auth") || joined.includes("otp") || joined.includes("mfa");
  const hasLogs = joined.includes("audit") || joined.includes("log");
  const hasSecrets = joined.includes("secret") || joined.includes("credential") || joined.includes("password") || joined.includes("api_key");
  const privilegedEvidence = collectEvidence(samples, [/ipcMain/i, /\b(auth|login|session|token|role)\b/i, /scan|export|threat model/i]);
  const exportEvidence = collectEvidence(samples, [/writeFile/i, /export/i, /resolveOutputPath/i, /pdfkit/i]);
  const auditEvidence = collectEvidence(samples, [/audit/i, /history/i, /log/i]);
  const disclosureEvidence = collectEvidence(samples, [/secret/i, /credential/i, /password/i, /token/i, /snippet/i, /evidence/i]);
  const traversalEvidence = collectEvidence(samples, [/readdir/i, /rglob/i, /recursive/i, /collectFiles/i]);
  const privilegeEvidence = collectEvidence(samples, [/ipcMain/i, /contextBridge/i, /main process/i, /renderer/i]);

  if (hasAuth || hasPrivilegedHandlers) {
    const score = estimateThreatScore("High", "Medium", hasPrivilegedHandlers ? "Authenticated" : "Public");
    const evidence = privilegedEvidence.length > 0 ? privilegedEvidence : collectEvidence(samples, [/auth/i, /token/i, /session/i]);
    if (evidence.length > 0) {
    threats.push({
      threat_id: nextId(),
      title: "Renderer or caller can influence privileged operations",
      component: components.includes("Desktop service") ? "Desktop service IPC" : "Backend route handling",
      stride_category: "Spoofing",
      description: "Privilege-sensitive actions are exposed through callable handlers or endpoints that must not trust caller-supplied role or identity data.",
      abuse_case: "Attacker forges a higher-privilege request or replays an old session claim to reach an operation that should only be available to privileged users.",
      impact: "High",
      likelihood: "Medium",
      exposure: hasPrivilegedHandlers ? "Authenticated" : "Public",
      risk_score: score,
      risk_level: scoreToLevel(score),
      review_status: "Pending reviewer validation",
      root_cause: evidence[0].excerpt,
      evidence,
      mitigation: "Enforce authorization server-side for every privileged handler, derive identity from verified session state, and reject caller-supplied role claims.",
    });
    }
  }

  if (hasExports || externalIntegrations.includes("Filesystem") || externalIntegrations.includes("Local report/export folder")) {
    const score = estimateThreatScore("High", "Medium", "Authenticated");
    const evidence = exportEvidence.length > 0 ? exportEvidence : collectEvidence(samples, [/export/i, /writeFile/i, /resolveOutputPath/i]);
    if (evidence.length > 0) {
    threats.push({
      threat_id: nextId(),
      title: "Path-controlled exports can tamper with local artifacts",
      component: "Report exporter / filesystem writer",
      stride_category: "Tampering",
      description: "Export and artifact-writing paths are influenced by repository or user input, so outputs must be normalized and confined to approved directories.",
      abuse_case: "Attacker crafts a target path or export name that overwrites a predictable local file or places a report where another process reads it as trusted input.",
      impact: "High",
      likelihood: "Medium",
      exposure: "Authenticated",
      risk_score: score,
      risk_level: scoreToLevel(score),
      review_status: "Pending reviewer validation",
      root_cause: evidence[0].excerpt,
      evidence,
      mitigation: "Canonicalize output paths, enforce a fixed export root, reject traversal segments, and ensure report names are sanitized before writing.",
    });
    }
  }

  if (hasLogs || joined.includes("history") || joined.includes("audit")) {
    const score = estimateThreatScore("Medium", "Medium", "Authenticated");
    const evidence = auditEvidence.length > 0 ? auditEvidence : collectEvidence(samples, [/audit/i, /history/i, /log/i]);
    if (evidence.length > 0) {
    threats.push({
      threat_id: nextId(),
      title: "Local audit trail can be cleared or bypassed",
      component: "Audit logging and history management",
      stride_category: "Repudiation",
      description: "If audit logs and history are stored locally without integrity protection, malicious users can erase traces of sensitive operations.",
      abuse_case: "User performs a high-risk action and then clears local history or resets the cache so there is no trustworthy evidence left behind.",
      impact: "Medium",
      likelihood: "Medium",
      exposure: "Authenticated",
      risk_score: score,
      risk_level: scoreToLevel(score),
      review_status: "Pending reviewer validation",
      root_cause: evidence[0].excerpt,
      evidence,
      mitigation: "Use append-only audit logging, add integrity metadata or signing, and keep audit retention separate from regular user-managed history cleanup.",
    });
    }
  }

  if (hasSecrets || hasExports || joined.includes("snippet") || joined.includes("evidence")) {
    const score = estimateThreatScore("High", "High", "Authenticated");
    const evidence = disclosureEvidence.length > 0 ? disclosureEvidence : collectEvidence(samples, [/secret/i, /credential/i, /password/i, /token/i, /snippet/i]);
    if (evidence.length > 0) {
    threats.push({
      threat_id: nextId(),
      title: "Reports can disclose code, paths, and secrets",
      component: "Threat model / report rendering pipeline",
      stride_category: "Information Disclosure",
      description: "Rendered reports, code evidence, and exported artifacts may expose source lines, paths, tokens, or other sensitive context.",
      abuse_case: "A user opens or exports a report and gains access to nearby code snippets, file paths, or secret material that should be redacted for their role.",
      impact: "High",
      likelihood: "High",
      exposure: "Authenticated",
      risk_score: score,
      risk_level: scoreToLevel(score),
      review_status: "Pending reviewer validation",
      root_cause: evidence[0].excerpt,
      evidence,
      mitigation: "Apply role-based redaction consistently, hide sensitive evidence by default for executive views, and avoid exporting secrets or raw credential material.",
    });
    }
  }

  if (hasRecursiveTraversal) {
    const score = estimateThreatScore("Medium", "High", "Public");
    const evidence = traversalEvidence.length > 0 ? traversalEvidence : collectEvidence(samples, [/readdir/i, /rglob/i, /recursive/i, /collectFiles/i]);
    if (evidence.length > 0) {
    threats.push({
      threat_id: nextId(),
      title: "Large repository traversal can exhaust local resources",
      component: "Source discovery and analysis engine",
      stride_category: "Denial of Service",
      description: "Recursive file discovery and deep analysis can become expensive on large repositories or on trees with many generated files.",
      abuse_case: "Attacker selects a very large tree or a path full of nested generated files and forces the analyzer to spend excessive CPU and memory.",
      impact: "Medium",
      likelihood: "High",
      exposure: "Public",
      risk_score: score,
      risk_level: scoreToLevel(score),
      review_status: "Pending reviewer validation",
      root_cause: evidence[0].excerpt,
      evidence,
      mitigation: "Cap file counts, skip generated directories, bound per-file size, and use worker/time limits for discovery, parsing, and rendering.",
    });
    }
  }

  if (components.includes("Desktop service") || components.includes("Analysis engine") || hasPrivilegedHandlers) {
    const score = estimateThreatScore("High", "Medium", "Internal");
    const evidence = privilegeEvidence.length > 0 ? privilegeEvidence : collectEvidence(samples, [/ipcMain/i, /contextBridge/i, /main process/i, /renderer/i]);
    if (evidence.length > 0) {
    threats.push({
      threat_id: nextId(),
      title: "Privileged desktop handlers can elevate access if authorization drifts",
      component: "Desktop service / backend service",
      stride_category: "Elevation of Privilege",
      description: "Privileged application handlers should never rely on UI state alone for authorization because renderer code can be manipulated locally.",
      abuse_case: "An attacker crafts IPC payloads or local state mutations to invoke operations that were intended only for administrators or tool owners.",
      impact: "High",
      likelihood: "Medium",
      exposure: "Internal",
      risk_score: score,
      risk_level: scoreToLevel(score),
      review_status: "Pending reviewer validation",
      root_cause: evidence[0].excerpt,
      evidence,
      mitigation: "Check authorization in the privileged layer, keep renderer claims advisory only, and restrict sensitive operations by validated session and role.",
    });
    }
  }

  return threats.map((threat) => adaptThreatForFramework(threat, framework));
}

function summarizeStrideCounts(threats: ThreatModelThreat[]): Record<ThreatModelThreat["stride_category"], number> {
  return threats.reduce(
    (acc, threat) => {
      acc[threat.stride_category] += 1;
      return acc;
    },
    {
      Spoofing: 0,
      Tampering: 0,
      Repudiation: 0,
      "Information Disclosure": 0,
      "Denial of Service": 0,
      "Elevation of Privilege": 0,
    } as Record<ThreatModelThreat["stride_category"], number>,
  );
}

function buildMermaidDiagram(report: ThreatModelReport): string {
  const body = [
    "flowchart TD",
    "  subgraph TB1[Trust boundary: User interface]",
    "    user([Operator]) -->|selects target codebase| ui[Application UI]",
    "  end",
    "  subgraph TB2[Trust boundary: privileged analysis]",
    "    ui -->|IPC request| bridge[Desktop service]",
    "    bridge -->|path + methodology| engine[Analysis engine]",
    "    engine -->|read source code| repo[(Target repository)]",
    "    engine -->|write JSON / HTML / Mermaid| store[(Generated artifacts)]",
    "  end",
    "  bridge -->|rendered model| ui",
  ];
  return body.join("\n");
}

function renderThreatDiagramPreview(report: ThreatModelReport): string {
  const frameworkLabel = threatModelFrameworkLabel(report.framework);
  const componentSummary = report.system_overview.main_components.slice(0, 3).join(", ") || "Selected codebase";
  const entryPointSummary = report.entry_points.length > 0 ? `${report.entry_points.length} entry points` : "No entry points found";
  const assetSummary = report.assets.length > 0 ? `${report.assets.length} assets` : "No assets inferred";
  const threatSummary = `${report.threats.length} threats`;
  const flowNodes = [
    { title: "Operator", detail: "Selects target codebase" },
    { title: "Application UI", detail: "Threat Modeling workspace" },
    { title: "Desktop service", detail: "IPC request and audit trail" },
    { title: "Analysis engine", detail: frameworkLabel },
    { title: "Target repository", detail: componentSummary },
    { title: "Generated artifacts", detail: `${assetSummary} | ${entryPointSummary} | ${threatSummary}` },
  ];
  return `
    <div class="diagram-preview" role="img" aria-label="Threat model flow diagram">
      <div class="diagram-boundary">Trust boundary: user interface</div>
      <div class="diagram-row">
        ${flowNodes
          .map(
            (node, index) => `
              <div class="diagram-node">
                <div class="diagram-node-title">${escapeHtml(node.title)}</div>
                <div class="diagram-node-detail">${escapeHtml(node.detail)}</div>
              </div>
              ${index < flowNodes.length - 1 ? `<div class="diagram-arrow">→</div>` : ""}
            `,
          )
          .join("")}
      </div>
      <div class="diagram-boundary">Trust boundary: privileged analysis</div>
    </div>
  `;
}

function buildAttackSurfaceSummary(entryPoints: ThreatModelEntryPoint[], components: string[], externalIntegrations: string[]): Array<{ label: string; value: string; detail: string }> {
  const routeEntries = entryPoints.filter((item) => item.type === "HTTP route");
  const ipcEntries = entryPoints.filter((item) => item.type === "Desktop IPC channel");
  const authEntries = entryPoints.filter((item) => item.type === "Authentication or access-control logic");
  const filePickers = entryPoints.filter((item) => item.type === "Local file selection");
  const rows: Array<{ label: string; value: string; detail: string }> = [];
  if (routeEntries.length > 0) {
    rows.push({
      label: "HTTP routes",
      value: String(routeEntries.length),
      detail: routeEntries.slice(0, 4).map((item) => `${item.name} (${item.file}:${item.line})`).join("; "),
    });
  }
  if (ipcEntries.length > 0) {
    rows.push({
      label: "Desktop IPC channels",
      value: String(ipcEntries.length),
      detail: ipcEntries.slice(0, 4).map((item) => `${item.name} (${item.file}:${item.line})`).join("; "),
    });
  }
  if (authEntries.length > 0) {
    rows.push({
      label: "Auth / access-control paths",
      value: String(authEntries.length),
      detail: authEntries.slice(0, 4).map((item) => `${item.name} (${item.file}:${item.line})`).join("; "),
    });
  }
  if (filePickers.length > 0) {
    rows.push({
      label: "Local file pickers",
      value: String(filePickers.length),
      detail: filePickers.slice(0, 4).map((item) => `${item.name} (${item.file}:${item.line})`).join("; "),
    });
  }
  if (components.includes("Analysis engine")) {
    rows.push({
      label: "Background analysis",
      value: "1",
      detail: "The analysis engine traverses the selected source tree and serializes threat model artifacts.",
    });
  }
  if (externalIntegrations.length > 0) {
    rows.push({
      label: "External integrations",
      value: String(externalIntegrations.length),
      detail: externalIntegrations.join(", "),
    });
  }
  return rows;
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
  const framework = report.framework;
  const frameworkLabel = threatModelFrameworkLabel(report.framework);
  const overviewList = report.system_overview.main_components.map((item) => `<li>${escapeHtml(item)}</li>`).join("");
  const integrationsList = report.system_overview.external_integrations.map((item) => `<li>${escapeHtml(item)}</li>`).join("");
  const stackList = report.system_overview.technology_stack.map((item) => `<li>${escapeHtml(item)}</li>`).join("");
  const categoryCounts = report.threats.reduce((acc, threat) => {
    const key = threat.framework_category || threat.stride_category;
    acc[key] = (acc[key] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);
  const categoryEntries = Object.entries(categoryCounts).sort((left, right) => right[1] - left[1]);
  const assetRows = report.assets
    .map(
      (item) => `<tr>
        <td>${escapeHtml(item.asset_id)}</td>
        <td>${escapeHtml(item.name)}</td>
        <td>${escapeHtml(item.category)}</td>
        <td>${escapeHtml(item.sensitivity)}</td>
        <td>${escapeHtml(item.location)}</td>
        <td>${escapeHtml(item.description)}</td>
      </tr>`,
    )
    .join("");
  const objectiveRows = report.security_objectives
    .map(
      (item) => `<tr>
        <td>${escapeHtml(item.asset_id)}</td>
        <td>${escapeHtml(item.confidentiality)}</td>
        <td>${escapeHtml(item.integrity)}</td>
        <td>${escapeHtml(item.availability)}</td>
        <td>${escapeHtml(item.rationale)}</td>
      </tr>`,
    )
    .join("");
  const surfaceRows = buildAttackSurfaceSummary(report.entry_points, report.system_overview.main_components, report.system_overview.external_integrations)
    .map(
      (item) => `<tr>
        <td>${escapeHtml(item.label)}</td>
        <td>${escapeHtml(item.value)}</td>
        <td>${escapeHtml(item.detail)}</td>
      </tr>`,
    )
    .join("");
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
        <td>${escapeHtml(item.threat_id || "")}</td>
        <td><strong>${escapeHtml(item.title)}</strong></td>
        <td>${escapeHtml(item.component)}</td>
        <td>${escapeHtml(item.framework_category || item.stride_category)}</td>
        <td>${escapeHtml(item.impact)}</td>
        <td>${escapeHtml(item.likelihood)}</td>
        <td>${escapeHtml(item.exposure)}</td>
        <td>${escapeHtml(String(item.risk_score ?? ""))} (${escapeHtml(item.risk_level || "")})</td>
        <td>${escapeHtml(item.review_status || "Pending reviewer validation")}</td>
        <td>${escapeHtml(item.root_cause || "")}</td>
        <td>${escapeHtml(item.abuse_case)}</td>
        <td>${escapeHtml(item.mitigation)}</td>
      </tr>`,
    )
    .join("");
  const strideCounts = summarizeStrideCounts(report.threats);
  const threatLinks = report.threats
    .map(
      (item, index) => `<a class="threat-link" href="#threat-${escapeHtml(item.threat_id || `TM-${index + 1}`)}">
        ${escapeHtml(item.threat_id || `TM-${index + 1}`)}: ${escapeHtml(item.title)}
      </a>`,
    )
    .join("");
  const threatCards = report.threats
    .map(
      (item, index) => `<details class="threat-card" id="threat-${escapeHtml(item.threat_id || `TM-${index + 1}`)}">
        <summary class="threat-head">
          <div>
            <p class="eyebrow">${escapeHtml(item.threat_id || `TM-${index + 1}`)}</p>
            <h3>${escapeHtml(item.title)}</h3>
          </div>
          <span class="stride">${escapeHtml(item.stride_category)}</span>
        </summary>
        <div class="threat-body">
          <p><strong>Component:</strong> ${escapeHtml(item.component)}</p>
          <p><strong>Methodology:</strong> ${escapeHtml(frameworkLabel)}</p>
          <p><strong>Classification:</strong> ${escapeHtml(item.framework_category || item.stride_category)}</p>
          <p><strong>Impact:</strong> ${escapeHtml(item.impact)} | <strong>Likelihood:</strong> ${escapeHtml(item.likelihood)} | <strong>Exposure:</strong> ${escapeHtml(item.exposure)}</p>
          <p><strong>Risk score:</strong> ${escapeHtml(String(item.risk_score ?? ""))} (${escapeHtml(item.risk_level || "")})</p>
          <p><strong>Review status:</strong> ${escapeHtml(item.review_status || "Pending review")}</p>
          <p><strong>Description:</strong> ${escapeHtml(item.description)}</p>
          ${item.owasp_category ? `<p><strong>OWASP Category:</strong> ${escapeHtml(item.owasp_category)}</p>` : ""}
          ${item.pasta_stage ? `<p><strong>PASTA Stage:</strong> ${escapeHtml(item.pasta_stage)}</p>` : ""}
          ${item.dread_breakdown ? `<table><thead><tr><th>Damage</th><th>Reproducibility</th><th>Exploitability</th><th>Affected Users</th><th>Discoverability</th></tr></thead><tbody><tr><td>${item.dread_breakdown.damage}</td><td>${item.dread_breakdown.reproducibility}</td><td>${item.dread_breakdown.exploitability}</td><td>${item.dread_breakdown.affected_users}</td><td>${item.dread_breakdown.discoverability}</td></tr></tbody></table>` : ""}
          <p><strong>Evidence:</strong></p>
          ${(item.evidence || []).length > 0
            ? `<ul>${(item.evidence || []).map((hit) => `<li>${escapeHtml(hit.file)}:${Number(hit.line || 0)} - ${escapeHtml(hit.excerpt)}</li>`).join("")}</ul>`
            : `<p class="muted">Needs reviewer validation.</p>`}
          <p><strong>Root cause:</strong> ${escapeHtml(item.root_cause || "Derived from the code evidence above.")}</p>
          <p><strong>Abuse case:</strong> ${escapeHtml(item.abuse_case)}</p>
          <p><strong>Mitigation:</strong> ${escapeHtml(item.mitigation)}</p>
        </div>
      </details>`,
    )
    .join("");

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>CodeSentinelX Threat Modeling Report</title>
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
    .threat-index { display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:10px; margin-top:14px; }
    .index-card { border:1px solid rgba(120,168,205,.18); border-radius:14px; padding:12px; background:rgba(255,255,255,.03); }
    .index-card .count { font-size:1.6rem; font-weight:700; margin:4px 0 0; }
    .threat-list { display:grid; grid-template-columns:repeat(auto-fit,minmax(320px,1fr)); gap:12px; margin-top:12px; }
    .threat-links { display:flex; flex-wrap:wrap; gap:8px; margin-top:12px; }
    .threat-link { display:inline-flex; align-items:center; padding:8px 10px; border-radius:999px; border:1px solid rgba(120,168,205,.18); background:rgba(255,255,255,.03); color:#d8e6f2; text-decoration:none; }
    .threat-link:hover { border-color: rgba(120,168,205,.42); background:rgba(255,255,255,.06); }
    .threat-card { border:1px solid rgba(120,168,205,.18); border-radius:14px; padding:0; background:#0a1421; overflow:hidden; }
    .threat-head { display:flex; justify-content:space-between; gap:12px; align-items:flex-start; margin-bottom:10px; }
    .threat-card > summary { cursor:pointer; list-style:none; padding:14px; }
    .threat-card > summary::-webkit-details-marker { display:none; }
    .threat-body { padding:0 14px 14px; }
    .eyebrow { margin:0; color:#9ab0c8; font-size:.78rem; letter-spacing:.08em; text-transform:uppercase; }
    .stride { display:inline-flex; align-items:center; border:1px solid rgba(120,168,205,.25); border-radius:999px; padding:6px 10px; background:rgba(255,255,255,.04); white-space:nowrap; }
    .diagram-preview { display:flex; flex-direction:column; gap:12px; }
    .diagram-boundary { display:inline-flex; align-self:flex-start; padding:6px 10px; border-radius:999px; border:1px solid rgba(120,168,205,.22); background:rgba(255,255,255,.03); color:#b8cadc; font-size:.82rem; }
    .diagram-row { display:grid; grid-template-columns:repeat(11, minmax(0, 1fr)); gap:10px; align-items:stretch; }
    .diagram-node { grid-column:span 2; min-height:92px; border:1px solid rgba(120,168,205,.22); border-radius:14px; padding:12px; background:linear-gradient(180deg, rgba(255,255,255,.05), rgba(255,255,255,.02)); display:flex; flex-direction:column; justify-content:center; text-align:center; }
    .diagram-node-title { font-weight:700; margin-bottom:6px; }
    .diagram-node-detail { color:#9ab0c8; font-size:.9rem; line-height:1.35; }
    .diagram-arrow { grid-column:span 1; display:flex; align-items:center; justify-content:center; color:#7ecbff; font-size:1.4rem; font-weight:700; }
    .diagram-help { color:#9ab0c8; font-size:.88rem; margin-top:-4px; }
  </style>
</head>
<body>
  <main class="shell">
    <section class="hero">
      <h1>CodeSentinelX Threat Modeling Report</h1>
      <p class="muted">${escapeHtml(frameworkLabel)} analysis generated from code only. This workflow is separate from the canonical scan pipeline.</p>
      <div class="meta">
        <div class="pill"><strong>Target:</strong> ${escapeHtml(report.target_path)}</div>
        <div class="pill"><strong>Type:</strong> ${escapeHtml(report.target_type)}</div>
        <div class="pill"><strong>Methodology:</strong> ${escapeHtml(frameworkLabel)}</div>
        <div class="pill"><strong>Generated:</strong> ${escapeHtml(report.generated_at)}</div>
        <div class="pill"><strong>Source files analyzed:</strong> ${report.summary.source_files_analyzed}</div>
        <div class="pill"><strong>Entry points:</strong> ${report.summary.entry_points}</div>
        <div class="pill"><strong>Threats:</strong> ${report.summary.threats}</div>
      </div>
      <div class="threat-index">
        <div class="index-card"><div>Assets</div><div class="count">${report.summary.assets}</div><div class="muted">Inventory items</div></div>
        <div class="index-card"><div>TM-1 to TM-${report.threats.length}</div><div class="count">${report.summary.threats}</div><div class="muted">Total threats</div></div>
        ${framework === "STRIDE"
          ? `<div class="index-card"><div>Spoofing</div><div class="count">${strideCounts.Spoofing}</div></div>
             <div class="index-card"><div>Tampering</div><div class="count">${strideCounts.Tampering}</div></div>
             <div class="index-card"><div>Repudiation</div><div class="count">${strideCounts.Repudiation}</div></div>
             <div class="index-card"><div>Information Disclosure</div><div class="count">${strideCounts["Information Disclosure"]}</div></div>
             <div class="index-card"><div>Denial of Service</div><div class="count">${strideCounts["Denial of Service"]}</div></div>
             <div class="index-card"><div>Elevation of Privilege</div><div class="count">${strideCounts["Elevation of Privilege"]}</div></div>`
          : categoryEntries.slice(0, 6).map(([category, count]) => `<div class="index-card"><div>${escapeHtml(category)}</div><div class="count">${count}</div></div>`).join("")}
      </div>
      <div class="threat-links">${threatLinks}</div>
    </section>

    <section class="grid">
      <article class="card">
        <h2>Executive Overview</h2>
        <p><strong>Application Type:</strong> ${escapeHtml(report.system_overview.application_type)}</p>
        ${overviewList ? `<h3>Main Components</h3><ul>${overviewList}</ul>` : ""}
        ${integrationsList ? `<h3>External Integrations</h3><ul>${integrationsList}</ul>` : ""}
        ${stackList ? `<h3>Technology Stack</h3><ul>${stackList}</ul>` : ""}
      </article>
      <article class="card">
        <h2>Architecture Diagram</h2>
        <p class="muted">Rendered flowchart for trust boundaries and high-level data movement.</p>
        <pre>${escapeHtml(report.diagram)}</pre>
      </article>
    </section>

    ${assetRows ? `
    <section class="card">
      <h2>Asset Inventory</h2>
      <table><thead><tr><th>ID</th><th>Name</th><th>Category</th><th>Sensitivity</th><th>Location</th><th>Description</th></tr></thead><tbody>${assetRows}</tbody></table>
    </section>` : ""}

    ${objectiveRows ? `
    <section class="card">
      <h2>Assets and Security Objectives</h2>
      <table><thead><tr><th>Asset</th><th>Confidentiality</th><th>Integrity</th><th>Availability</th><th>Rationale</th></tr></thead><tbody>${objectiveRows}</tbody></table>
    </section>` : ""}

    ${surfaceRows ? `
    <section class="card">
      <h2>Attack Surface</h2>
      <table><thead><tr><th>Surface</th><th>Count</th><th>Evidence</th></tr></thead><tbody>${surfaceRows}</tbody></table>
    </section>` : ""}

    ${entryRows ? `
    <section class="card">
      <h2>Entry Points</h2>
      <table>
        <thead><tr><th>Name</th><th>Type</th><th>Exposure</th><th>Location</th><th>Details</th></tr></thead>
        <tbody>${entryRows}</tbody>
      </table>
    </section>` : ""}

    ${boundaryRows ? `
    <section class="card">
      <h2>Trust Boundaries</h2>
      <table>
        <thead><tr><th>From</th><th>To</th><th>Data</th><th>Description</th></tr></thead>
        <tbody>${boundaryRows}</tbody>
      </table>
    </section>` : ""}

    ${flowRows ? `
    <section class="card">
      <h2>Data Flows</h2>
      <table>
        <thead><tr><th>Source</th><th>Destination</th><th>Data</th><th>Description</th></tr></thead>
        <tbody>${flowRows}</tbody>
      </table>
    </section>` : ""}

    ${report.threats.length > 0 ? `
    <section class="card">
      <h2>Threat Register (${escapeHtml(frameworkLabel)})</h2>
      <div class="threat-list">
        ${threatCards}
      </div>
      <h3 style="margin-top:18px;">Threat Table</h3>
      <table>
        <thead><tr><th>ID</th><th>Title</th><th>Component</th><th>Classification</th><th>Impact</th><th>Likelihood</th><th>Exposure</th><th>Risk</th><th>Review Status</th><th>Root Cause</th><th>Abuse Case</th><th>Mitigation</th></tr></thead>
        <tbody>${threatRows}</tbody>
      </table>
      ${categoryEntries.length > 0 ? `<h3 style="margin-top:18px;">Methodology Category Breakdown</h3><table><thead><tr><th>Category</th><th>Count</th></tr></thead><tbody>${categoryEntries.map(([category, count]) => `<tr><td>${escapeHtml(category)}</td><td>${count}</td></tr>`).join("")}</tbody></table>` : ""}
    </section>` : ""}

    ${report.code_mappings.length > 0 ? `
    <section class="card">
      <h2>Vulnerabilities Mapped to Code</h2>
      <table><thead><tr><th>Threat</th><th>Component</th><th>File</th><th>Line</th><th>Root Cause</th><th>CWE</th></tr></thead><tbody>${report.code_mappings.map((item) => `<tr><td>${escapeHtml(item.threat_id)}</td><td>${escapeHtml(item.component)}</td><td>${escapeHtml(item.file)}</td><td>${Number(item.line || 0)}</td><td>${escapeHtml(item.root_cause)}</td><td>${escapeHtml(item.cwe || "")}</td></tr>`).join("")}</tbody></table>
    </section>` : ""}

    ${report.threats.length > 0 ? `
    <section class="card">
      <h2>Risk Assessment</h2>
      <table><thead><tr><th>Threat</th><th>Risk</th><th>Level</th><th>Justification</th></tr></thead><tbody>${report.threats.map((item) => `<tr><td>${escapeHtml(item.threat_id || item.title)}</td><td>${escapeHtml(String(item.risk_score ?? ""))}</td><td>${escapeHtml(item.risk_level || "")}</td><td>${escapeHtml(item.impact)} impact / ${escapeHtml(item.likelihood)} likelihood / ${escapeHtml(item.exposure)} exposure</td></tr>`).join("")}</tbody></table>
    </section>` : ""}

    ${report.threats.length > 0 ? `
    <section class="card">
      <h2>Mitigations</h2>
      <table><thead><tr><th>Threat</th><th>Mitigation</th></tr></thead><tbody>${report.threats.map((item) => `<tr><td>${escapeHtml(item.threat_id || item.title)}</td><td>${escapeHtml(item.mitigation)}</td></tr>`).join("")}</tbody></table>
    </section>` : ""}

    ${report.validation_plan.length > 0 ? `
    <section class="card">
      <h2>Validation & Test Strategy</h2>
      <table><thead><tr><th>Threat</th><th>Check</th><th>Expected Verification</th></tr></thead><tbody>${report.validation_plan.map((item) => `<tr><td>${escapeHtml(item.threat_id)}</td><td>${escapeHtml(item.check)}</td><td>${escapeHtml(item.expected_verification)}</td></tr>`).join("")}</tbody></table>
    </section>` : ""}

    ${report.traceability.length > 0 ? `
    <section class="card">
      <h2>Traceability</h2>
      <table><thead><tr><th>Threat</th><th>Evidence</th><th>Status</th></tr></thead><tbody>${report.traceability.map((item) => `<tr><td>${escapeHtml(item.threat_id)}</td><td>${escapeHtml(item.evidence)}</td><td>${escapeHtml(item.status)}</td></tr>`).join("")}</tbody></table>
    </section>` : ""}

    ${(report.residual_risk.length > 0 || report.assumptions.length > 0) ? `
    <section class="card">
      <h2>Residual Risk & Assumptions</h2>
      ${report.residual_risk.length > 0 ? `<h3>Residual Risk</h3><ul>${report.residual_risk.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul>` : ""}
      ${report.assumptions.length > 0 ? `<h3>Assumptions</h3><ul>${report.assumptions.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul>` : ""}
    </section>` : ""}

    <section class="two-col">
      <article class="card code-box">
        <h2>JSON</h2>
        <pre>${escapeHtml(JSON.stringify(report, null, 2))}</pre>
      </article>
      <article class="card code-box">
        <h2>Architecture Diagram</h2>
        ${renderThreatDiagramPreview(report)}
        <details style="margin-top:12px;">
          <summary class="diagram-help">View diagram source</summary>
          <pre>${escapeHtml(report.diagram)}</pre>
        </details>
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
    const framework = normalizeThreatModelFramework(request.framework);
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
    const assets = buildAssets(samples, entryPoints, mainComponents, externalIntegrations);
    const securityObjectives = buildSecurityObjectives(assets);
    const dataFlows = buildDataFlows(mainComponents, entryPoints);
    const threats = buildThreats(samples, entryPoints, mainComponents, externalIntegrations, framework);
    const trustBoundaries = buildTrustBoundaries(entryPoints, mainComponents, externalIntegrations);
    const codeMappings = buildCodeMappings(threats);
    const validationPlan = buildValidationPlan(threats);
    const traceability = buildTraceability(threats);
    const residualRisk = buildResidualRisk(threats);
    const assumptions = buildAssumptions(samples, mainComponents);
    const report: ThreatModelReport = {
      schema_version: "codesentinelx.threat_model.v1",
      target_path: resolved,
      target_type: stat.isFile() ? "file" : "folder",
      generated_at: new Date().toISOString(),
      framework,
      system_overview: {
        application_type: detectApplicationType(samples),
        main_components: mainComponents,
        external_integrations: externalIntegrations,
        technology_stack: detectTechnologyStack(samples),
      },
      assets,
      security_objectives: securityObjectives,
      entry_points: entryPoints,
      trust_boundaries: trustBoundaries,
      data_flows: dataFlows,
      code_mappings: codeMappings,
      threats,
      validation_plan: validationPlan,
      traceability,
      residual_risk: residualRisk,
      assumptions,
      diagram: "",
      summary: {
        source_files_analyzed: samples.length,
        assets: assets.length,
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
    const frameworkSlug = framework.toLowerCase();
    const targetDir = path.join(this.outputDir, "threat-models", safeName, frameworkSlug);
    await fs.promises.mkdir(targetDir, { recursive: true });
    const jsonPath = path.join(targetDir, `${timestamp}_${frameworkSlug}_threat_model.json`);
    const mermaidPath = path.join(targetDir, `${timestamp}_${frameworkSlug}_threat_model.mmd`);
    const htmlPath = path.join(targetDir, `${timestamp}_${frameworkSlug}_threat_model.html`);
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
