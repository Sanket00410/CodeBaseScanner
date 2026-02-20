import { ScanProgressPayload, ScanRequest, UniversalScanReport, VulnerabilityFinding } from "./types";

interface RuntimeScanResult {
  report: UniversalScanReport;
  startedAt: string;
  completedAt: string;
  warnings: string[];
}

interface ProbeResponse {
  path: string;
  status: number;
  ok: boolean;
  headers: Record<string, string>;
  body: string;
}

const PROBES = [
  "/",
  "/robots.txt",
  "/sitemap.xml",
  "/swagger.json",
  "/openapi.json",
  "/actuator/health",
  "/actuator/env",
  "/.env",
  "/.git/config",
  "/admin",
  "/debug",
];

export class RuntimeIpScanner {
  async runScan(
    scanId: string,
    request: ScanRequest,
    onProgress: (payload: ScanProgressPayload) => void,
  ): Promise<RuntimeScanResult> {
    const startedAt = new Date().toISOString();
    const warnings: string[] = [];
    const findings: VulnerabilityFinding[] = [];

    const baseUrl = normalizeTarget(request.projectPath);
    let probesDone = 0;
    const totalSteps = PROBES.length + 2;

    onProgress({
      scanId,
      stage: "runtime_probe",
      progress: 1,
      message: `Starting runtime scan for ${baseUrl.origin}`,
      status: "running",
    });

    const responses = new Map<string, ProbeResponse>();
    for (const path of PROBES) {
      probesDone += 1;
      const progress = Math.min(95, Math.round((probesDone / totalSteps) * 100));
      onProgress({
        scanId,
        stage: "runtime_probe",
        progress,
        currentFile: path,
        message: `Probing ${path}`,
        status: "running",
      });

      try {
        const response = await fetchWithTimeout(new URL(path, baseUrl).toString(), 6000);
        responses.set(path, response);
      } catch (error) {
        warnings.push(`${path}: ${error instanceof Error ? error.message : String(error)}`);
      }
    }

    buildFindingsFromResponses(baseUrl, responses, findings);
    const report = buildRuntimeReport(baseUrl, findings, warnings);
    const completedAt = new Date().toISOString();

    onProgress({
      scanId,
      stage: "completed",
      progress: 100,
      message: "Runtime IP scan completed",
      status: "completed",
    });

    return {
      report,
      startedAt,
      completedAt,
      warnings,
    };
  }
}

export function isNetworkTarget(value: string): boolean {
  const target = value.trim();
  if (!target) {
    return false;
  }
  if (/^https?:\/\//i.test(target)) {
    return true;
  }
  if (/^\d{1,3}(\.\d{1,3}){3}(:\d+)?(\/.*)?$/.test(target)) {
    return true;
  }
  if (/^[a-z0-9.-]+\.[a-z]{2,}(:\d+)?(\/.*)?$/i.test(target)) {
    return true;
  }
  return false;
}

function normalizeTarget(rawTarget: string): URL {
  const target = rawTarget.trim();
  if (!isNetworkTarget(target)) {
    throw new Error("Target is not a valid IP or URL.");
  }
  const withScheme = /^https?:\/\//i.test(target) ? target : `http://${target}`;
  return new URL(withScheme);
}

async function fetchWithTimeout(url: string, timeoutMs: number): Promise<ProbeResponse> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, {
      method: "GET",
      redirect: "follow",
      signal: controller.signal,
      headers: {
        "User-Agent": "CodeSentinelX-RuntimeProbe/1.0",
      },
    });
    const body = await response.text();
    const headers: Record<string, string> = {};
    response.headers.forEach((value, key) => {
      headers[key.toLowerCase()] = value;
    });

    return {
      path: new URL(url).pathname || "/",
      status: response.status,
      ok: response.ok,
      headers,
      body: body.slice(0, 5000),
    };
  } finally {
    clearTimeout(timer);
  }
}

function buildFindingsFromResponses(baseUrl: URL, responses: Map<string, ProbeResponse>, findings: VulnerabilityFinding[]): void {
  const root = responses.get("/");
  if (!root) {
    findings.push(
      createFinding(baseUrl, "/", {
        ruleId: "RUNTIME-UNREACHABLE-001",
        severity: "Critical",
        title: "Target Service Unreachable",
        cwe: "CWE-16",
        owasp: "A05:2021 - Security Misconfiguration",
        impact: "Runtime target could not be reached. Security posture cannot be validated.",
        recommendation: "Verify target availability, firewall rules, and reverse proxy routing before scanning.",
      }),
    );
    return;
  }

  if (baseUrl.protocol === "http:") {
    findings.push(
      createFinding(baseUrl, "/", {
        ruleId: "RUNTIME-TRANSPORT-001",
        severity: "High",
        title: "Insecure Transport (HTTP)",
        cwe: "CWE-319",
        owasp: "A02:2021 - Cryptographic Failures",
        impact: "Traffic is exposed to interception and credential theft over plaintext transport.",
        recommendation: "Enforce HTTPS with HSTS and redirect all HTTP traffic to TLS endpoints.",
      }),
    );
  }

  const requiredHeaders: Array<{
    key: string;
    title: string;
    severity: VulnerabilityFinding["severity"];
    cwe: string;
    owasp: string;
    recommendation: string;
  }> = [
    {
      key: "content-security-policy",
      title: "Missing Content Security Policy",
      severity: "Medium",
      cwe: "CWE-693",
      owasp: "A05:2021 - Security Misconfiguration",
      recommendation: "Define a strict CSP and disallow inline scripts where possible.",
    },
    {
      key: "x-frame-options",
      title: "Missing X-Frame-Options Header",
      severity: "Medium",
      cwe: "CWE-1021",
      owasp: "A05:2021 - Security Misconfiguration",
      recommendation: "Set X-Frame-Options to DENY or SAMEORIGIN.",
    },
    {
      key: "x-content-type-options",
      title: "Missing X-Content-Type-Options Header",
      severity: "Low",
      cwe: "CWE-16",
      owasp: "A05:2021 - Security Misconfiguration",
      recommendation: "Set X-Content-Type-Options to nosniff.",
    },
    {
      key: "referrer-policy",
      title: "Missing Referrer-Policy Header",
      severity: "Low",
      cwe: "CWE-359",
      owasp: "A01:2021 - Broken Access Control",
      recommendation: "Set Referrer-Policy to strict-origin-when-cross-origin or stricter.",
    },
  ];

  for (const header of requiredHeaders) {
    if (!root.headers[header.key]) {
      findings.push(
        createFinding(baseUrl, "/", {
          ruleId: `RUNTIME-HEADER-${header.key.toUpperCase().replaceAll("-", "_")}`,
          severity: header.severity,
          title: header.title,
          cwe: header.cwe,
          owasp: header.owasp,
          impact: `${header.title} increases exploitability of client-side and browser-based attacks.`,
          recommendation: header.recommendation,
          evidence: `Response header '${header.key}' was not present on ${baseUrl.origin}.`,
        }),
      );
    }
  }

  if (baseUrl.protocol === "https:" && !root.headers["strict-transport-security"]) {
    findings.push(
      createFinding(baseUrl, "/", {
        ruleId: "RUNTIME-HEADER-HSTS-001",
        severity: "Medium",
        title: "Missing HSTS Header",
        cwe: "CWE-319",
        owasp: "A02:2021 - Cryptographic Failures",
        impact: "Clients may downgrade to insecure HTTP without strict transport enforcement.",
        recommendation: "Set Strict-Transport-Security with long max-age and includeSubDomains.",
      }),
    );
  }

  if (root.headers["access-control-allow-origin"] === "*") {
    const allowCredentials = root.headers["access-control-allow-credentials"] === "true";
    findings.push(
      createFinding(baseUrl, "/", {
        ruleId: "RUNTIME-CORS-001",
        severity: allowCredentials ? "High" : "Medium",
        title: "Overly Permissive CORS Configuration",
        cwe: "CWE-942",
        owasp: "A05:2021 - Security Misconfiguration",
        impact: "Untrusted origins can issue browser requests and potentially read sensitive responses.",
        recommendation: "Replace wildcard origins with explicit allowlist and disable credentialed wildcard CORS.",
        evidence: `access-control-allow-origin: *${allowCredentials ? " with credentials=true" : ""}`,
      }),
    );
  }

  const serverHeader = root.headers.server || root.headers["x-powered-by"] || "";
  if (serverHeader) {
    findings.push(
      createFinding(baseUrl, "/", {
        ruleId: "RUNTIME-TECH-DISCLOSURE-001",
        severity: "Low",
        title: "Technology Stack Disclosure",
        cwe: "CWE-200",
        owasp: "A05:2021 - Security Misconfiguration",
        impact: "Version and framework disclosure helps attackers optimize exploit selection.",
        recommendation: "Suppress detailed server banners and remove framework signature headers.",
        evidence: serverHeader,
      }),
    );
  }

  if (/index of\s*\//i.test(root.body)) {
    findings.push(
      createFinding(baseUrl, "/", {
        ruleId: "RUNTIME-DIRLISTING-001",
        severity: "Medium",
        title: "Directory Listing Exposed",
        cwe: "CWE-548",
        owasp: "A05:2021 - Security Misconfiguration",
        impact: "Browsable directory indexes can expose sensitive files and internal structure.",
        recommendation: "Disable directory listing on the web server and block direct listing endpoints.",
      }),
    );
  }

  checkSensitiveEndpoint(responses, "/swagger.json", "Public API Schema Exposed", "A05:2021 - Security Misconfiguration", "CWE-200", "Medium", findings, baseUrl);
  checkSensitiveEndpoint(responses, "/openapi.json", "Public API Schema Exposed", "A05:2021 - Security Misconfiguration", "CWE-200", "Medium", findings, baseUrl);
  checkSensitiveEndpoint(responses, "/actuator/health", "Actuator Endpoint Exposed", "A05:2021 - Security Misconfiguration", "CWE-200", "Medium", findings, baseUrl);
  checkSensitiveEndpoint(responses, "/actuator/env", "Actuator Endpoint Exposed", "A05:2021 - Security Misconfiguration", "CWE-200", "High", findings, baseUrl);
  checkSensitiveEndpoint(responses, "/.env", "Environment File Exposure", "A02:2021 - Cryptographic Failures", "CWE-200", "Critical", findings, baseUrl);
  checkSensitiveEndpoint(responses, "/.git/config", "Git Metadata Exposure", "A05:2021 - Security Misconfiguration", "CWE-200", "High", findings, baseUrl);
  checkSensitiveEndpoint(responses, "/admin", "Admin Endpoint Publicly Reachable", "A01:2021 - Broken Access Control", "CWE-284", "Medium", findings, baseUrl);
  checkSensitiveEndpoint(responses, "/debug", "Debug Endpoint Exposed", "A05:2021 - Security Misconfiguration", "CWE-489", "Medium", findings, baseUrl);
}

function checkSensitiveEndpoint(
  responses: Map<string, ProbeResponse>,
  endpoint: string,
  title: string,
  owasp: string,
  cwe: string,
  severity: VulnerabilityFinding["severity"],
  findings: VulnerabilityFinding[],
  baseUrl: URL,
): void {
  const response = responses.get(endpoint);
  if (!response) {
    return;
  }
  if (response.status >= 200 && response.status < 300) {
    findings.push(
      createFinding(baseUrl, endpoint, {
        ruleId: `RUNTIME-ENDPOINT-${endpoint.replaceAll("/", "_").replaceAll(".", "_").toUpperCase()}`,
        severity,
        title,
        cwe,
        owasp,
        impact: `${endpoint} is reachable from network and may leak sensitive operational metadata.`,
        recommendation: "Restrict endpoint access with authentication, network allowlisting, or disable endpoint in production.",
        evidence: `HTTP ${response.status} returned for ${endpoint}`,
      }),
    );
  }
}

function createFinding(
  baseUrl: URL,
  resourcePath: string,
  input: {
    ruleId: string;
    severity: VulnerabilityFinding["severity"];
    title: string;
    cwe: string;
    owasp: string;
    impact: string;
    recommendation: string;
    evidence?: string;
  },
): VulnerabilityFinding {
  const location = `${baseUrl.origin}${resourcePath}`;
  const cvss = severityToCvss(input.severity);
  return {
    finding_uid: `${input.ruleId}::${location}::1`,
    vulnerability_title: input.title,
    vulnerability_type: input.title,
    severity: input.severity,
    cvss_score: cvss,
    cwe_id: input.cwe,
    owasp_mapping: input.owasp,
    file_path: location,
    line_number: 1,
    business_impact: input.impact,
    recommendation: input.recommendation,
    original_code: input.evidence || `Runtime observation at ${location}`,
    fixed_code: input.recommendation,
    patch_preview: `# Runtime finding at ${location}\n# Apply remediation through infrastructure or application configuration.`,
    rule_id: input.ruleId,
    evidence_sources: ["Runtime-IP-Probe"],
    affected_module: getModule(location),
    tool: "Runtime-IP-Probe",
    status: "Open",
  };
}

function buildRuntimeReport(baseUrl: URL, findings: VulnerabilityFinding[], warnings: string[]): UniversalScanReport {
  const severityDistribution = summarizeSeverity(findings);
  const riskScore = calculateRiskScore(severityDistribution);
  const riskRating = scoreToRating(riskScore);
  const topTypes = toTopTypes(findings.map((item) => item.vulnerability_title || item.vulnerability_type || "Issue"));
  const topOwasp = toTopOwasp(findings.map((item) => item.owasp_mapping || "N/A"));
  const affectedModules = toAffectedModules(findings);
  const generatedAt = new Date().toISOString();

  return {
    scanner: {
      name: "CodeSentinelX Runtime Probe",
      version: "1.0.0",
    },
    executive_summary: {
      target_path: baseUrl.origin,
      generated_at: generatedAt,
      files_scanned: PROBES.length,
      total_vulnerabilities: findings.length,
      deduplicated_vulnerabilities: findings.length,
      duplicate_findings_removed: 0,
      total_files_impacted: new Set(findings.map((item) => item.file_path)).size,
      active_risk_findings: (severityDistribution.Critical || 0) + (severityDistribution.High || 0),
      assessment_confidence: warnings.length > 4 ? "Medium" : "High",
      severity_distribution: severityDistribution,
      risk_score: riskScore,
      risk_rating: riskRating,
      top_vulnerability_types: topTypes,
      top_owasp_categories: topOwasp,
      affected_modules: affectedModules,
      recommended_action_plan: buildActionPlan(severityDistribution),
      implemented_controls: 0,
    },
    existing_implementation_report: {
      report_type: "existing_implementation",
      title: "Existing Security Implementation Report",
      target_path: baseUrl.origin,
      generated_at: generatedAt,
      summary: {
        implemented_controls: 0,
        category_distribution: {},
        coverage_levels: {},
        standards_coverage: {},
      },
      controls: [],
      compliance_matrix: [],
    },
    vulnerability_fixed_code_report: {
      report_type: "vulnerability_fixed_code",
      title: "Vulnerability and Fixed-Code Report",
      target_path: baseUrl.origin,
      generated_at: generatedAt,
      summary: {
        total_findings: findings.length,
        raw_findings_total: findings.length,
        duplicate_findings_removed: 0,
        severity_distribution: severityDistribution,
        risk_score: riskScore,
        risk_rating: riskRating,
        active_risk_findings: (severityDistribution.Critical || 0) + (severityDistribution.High || 0),
        files_impacted: new Set(findings.map((item) => item.file_path)).size,
        top_vulnerability_types: topTypes,
        top_owasp_categories: topOwasp,
        affected_modules: affectedModules,
        open_findings: findings.length,
        reviewed_findings: 0,
      },
      findings,
      auto_fix_recommendations: findings.map((item) => ({
        priority: item.severity,
        cvss_score: item.cvss_score,
        vulnerability_title: item.vulnerability_title,
        file_path: item.file_path,
        line_number: item.line_number,
        recommended_fix: item.recommendation,
        original_code: item.original_code,
        fixed_code: item.fixed_code,
        patch_preview: item.patch_preview,
        autofix_confidence: "Low",
        automation_hint: "Apply remediation via app configuration and deployment controls.",
      })),
      toolchain_status: {
        runtime_probe: {
          name: "runtime_probe",
          available: true,
          command: "builtin",
          source: "builtin",
          message: warnings.length > 0 ? `Completed with ${warnings.length} warnings` : "Completed successfully",
        },
      },
    },
    existing_security_measures: {
      summary: {
        implemented_controls: 0,
        category_distribution: {},
        standards_coverage: {},
        coverage_levels: {},
      },
      controls: [],
      compliance_matrix: [],
    },
    vulnerability_findings: {
      summary: {
        total: findings.length,
        raw_total: findings.length,
        duplicate_reduction: 0,
        severity_distribution: severityDistribution,
        top_vulnerability_types: topTypes,
      },
      findings,
      toolchain_status: {
        runtime_probe: {
          name: "runtime_probe",
          available: true,
          command: "builtin",
          source: "builtin",
          message: warnings.length > 0 ? `Completed with ${warnings.length} warnings` : "Completed successfully",
        },
      },
    },
    auto_fix_recommendations: findings.map((item) => ({
      priority: item.severity,
      cvss_score: item.cvss_score,
      vulnerability_title: item.vulnerability_title,
      file_path: item.file_path,
      line_number: item.line_number,
      recommended_fix: item.recommendation,
      original_code: item.original_code,
      fixed_code: item.fixed_code,
      patch_preview: item.patch_preview,
      autofix_confidence: "Low",
      automation_hint: "Apply remediation via app configuration and deployment controls.",
    })),
    technical_report: {
      scan_window: {
        started_at: generatedAt,
        completed_at: generatedAt,
        duration_seconds: 0,
      },
      findings,
      errors: warnings,
    },
  };
}

function summarizeSeverity(findings: VulnerabilityFinding[]): Record<string, number> {
  const distribution: Record<string, number> = {
    Critical: 0,
    High: 0,
    Medium: 0,
    Low: 0,
    Info: 0,
  };
  for (const finding of findings) {
    distribution[finding.severity] = (distribution[finding.severity] || 0) + 1;
  }
  return distribution;
}

function calculateRiskScore(distribution: Record<string, number>): number {
  const total = Object.values(distribution).reduce((sum, value) => sum + value, 0);
  if (total === 0) {
    return 0;
  }
  const weights: Record<string, number> = { Critical: 10, High: 7, Medium: 4, Low: 1, Info: 0 };
  const weighted = Object.entries(distribution).reduce((sum, [severity, count]) => sum + count * (weights[severity] || 0), 0);
  const severityFactor = (weighted / (total * 10)) * 60;
  const countFactor = Math.min(total / 50, 1) * 40;
  return Math.round((severityFactor + countFactor) * 100) / 100;
}

function scoreToRating(score: number): string {
  if (score >= 80) {
    return "Critical";
  }
  if (score >= 60) {
    return "High";
  }
  if (score >= 35) {
    return "Medium";
  }
  if (score > 0) {
    return "Low";
  }
  return "Informational";
}

function severityToCvss(severity: VulnerabilityFinding["severity"]): number {
  const mapping: Record<VulnerabilityFinding["severity"], number> = {
    Critical: 9.8,
    High: 8.3,
    Medium: 6.4,
    Low: 3.7,
    Info: 0,
  };
  return mapping[severity];
}

function toTopTypes(values: string[]): Array<{ type: string; count: number }> {
  const counts = new Map<string, number>();
  for (const value of values) {
    counts.set(value, (counts.get(value) || 0) + 1);
  }
  const sorted = [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 10);
  return sorted.map(([type, count]) => ({ type, count }));
}

function toTopOwasp(values: string[]): Array<{ owasp_category: string; count: number }> {
  const counts = new Map<string, number>();
  for (const value of values) {
    counts.set(value, (counts.get(value) || 0) + 1);
  }
  const sorted = [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 10);
  return sorted.map(([owasp_category, count]) => ({ owasp_category, count }));
}

function toAffectedModules(findings: VulnerabilityFinding[]): Array<{ module: string; count: number; critical: number; high: number }> {
  const map = new Map<string, { count: number; critical: number; high: number }>();
  for (const finding of findings) {
    const module = getModule(finding.file_path);
    if (!map.has(module)) {
      map.set(module, { count: 0, critical: 0, high: 0 });
    }
    const entry = map.get(module)!;
    entry.count += 1;
    if (finding.severity === "Critical") {
      entry.critical += 1;
    }
    if (finding.severity === "High") {
      entry.high += 1;
    }
  }
  return [...map.entries()]
    .sort((a, b) => b[1].count - a[1].count)
    .slice(0, 12)
    .map(([module, stats]) => ({
      module,
      count: stats.count,
      critical: stats.critical,
      high: stats.high,
    }));
}

function getModule(location: string): string {
  try {
    const parsed = new URL(location);
    const pathParts = parsed.pathname.replace(/^\/+/, "").split("/").filter(Boolean);
    return pathParts[0] || parsed.host;
  } catch {
    return location;
  }
}

function buildActionPlan(distribution: Record<string, number>): string[] {
  const plan: string[] = [];
  if ((distribution.Critical || 0) > 0) {
    plan.push("Immediately remediate Critical runtime exposures that can leak secrets or allow takeover.");
  }
  if ((distribution.High || 0) > 0) {
    plan.push("Prioritize High runtime findings in current sprint and validate controls through retesting.");
  }
  if ((distribution.Medium || 0) > 0) {
    plan.push("Address Medium findings through hardening backlog and platform configuration updates.");
  }
  plan.push("Enable continuous runtime scanning for public endpoints and include evidence in release gates.");
  plan.push("Restrict sensitive endpoints and enforce security headers at edge/load balancer level.");
  return plan;
}
