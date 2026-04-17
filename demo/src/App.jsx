import { useMemo, useState } from "react";

const roles = {
  Admin: {
    tone: "full",
    subtitle: "Full scope execution and evidence review",
    scope: "Runs the broadest toolset across the whole repository with raw evidence and full drill-down.",
    report: "Combined + Vulnerability + Fixes + Existing",
    tools: ["Semgrep", "CodeQL", "OSV-Scanner", "Gitleaks", "ESLint Security", "Checkov"],
    summary: { critical: 11, high: 24, medium: 37, low: 13, info: 4, score: 86.2 },
    chart: [
      { label: "Critical", value: 11, color: "#ff6b6b" },
      { label: "High", value: 24, color: "#ff9f43" },
      { label: "Medium", value: 37, color: "#ffd166" },
      { label: "Low", value: 13, color: "#6ee7a2" },
      { label: "Info", value: 4, color: "#8ab4ff" },
    ],
    findings: [
      { severity: "Critical", title: "SQL Injection", file: "user_service/api.py", cwe: "CWE-89" },
      { severity: "High", title: "Weak Cryptography Usage", file: "auth/crypto.js", cwe: "CWE-327" },
      { severity: "High", title: "Hardcoded Secret", file: ".env.prod", cwe: "CWE-798" },
    ],
  },
  "Security Analyst": {
    tone: "security",
    subtitle: "Broad analysis with triage and prioritization",
    scope: "Focuses on exploitable findings, KEV correlation, and grouped attack paths with less noise than Admin.",
    report: "Vulnerability + Combined + Active PoC focus",
    tools: ["Semgrep", "OSV-Scanner", "CodeQL", "Gitleaks", "Grype"],
    summary: { critical: 7, high: 19, medium: 31, low: 7, info: 2, score: 79.4 },
    chart: [
      { label: "Critical", value: 7, color: "#ff6b6b" },
      { label: "High", value: 19, color: "#ff9f43" },
      { label: "Medium", value: 31, color: "#ffd166" },
      { label: "Low", value: 7, color: "#6ee7a2" },
      { label: "Info", value: 2, color: "#8ab4ff" },
    ],
    findings: [
      { severity: "Critical", title: "Broken Access Control", file: "orders/routes.ts", cwe: "CWE-284" },
      { severity: "High", title: "Dependency Vulnerability", file: "package-lock.json", cwe: "CWE-1104" },
      { severity: "High", title: "Command Injection", file: "jobs/runner.go", cwe: "CWE-78" },
    ],
  },
  Developer: {
    tone: "fix",
    subtitle: "Developer-ready remediation and PoC verification",
    scope: "Shows fix guidance, code locations, and verification steps for repo-relevant issues only.",
    report: "Fixes + Detailed Findings + Proof of repair",
    tools: ["Semgrep", "OSV-Scanner", "CodeQL", "Bandit", "ESLint Security"],
    summary: { critical: 5, high: 16, medium: 22, low: 8, info: 1, score: 73.1 },
    chart: [
      { label: "Critical", value: 5, color: "#ff6b6b" },
      { label: "High", value: 16, color: "#ff9f43" },
      { label: "Medium", value: 22, color: "#ffd166" },
      { label: "Low", value: 8, color: "#6ee7a2" },
      { label: "Info", value: 1, color: "#8ab4ff" },
    ],
    findings: [
      { severity: "Critical", title: "SQL Injection", file: "user_service/db.py", cwe: "CWE-89" },
      { severity: "High", title: "Weak Cryptography Usage", file: "auth/hash.ts", cwe: "CWE-327" },
      { severity: "Medium", title: "Insecure Logging", file: "logger/main.py", cwe: "CWE-532" },
    ],
  },
  Auditor: {
    tone: "audit",
    subtitle: "Redacted evidence with traceable control coverage",
    scope: "Shows compliance posture, controls, and redacted drill-down without overexposing raw secrets.",
    report: "Existing + Compliance + Audit evidence",
    tools: ["OSV-Scanner", "Semgrep", "Checkov", "Gitleaks"],
    summary: { critical: 3, high: 8, medium: 11, low: 5, info: 0, score: 68.7 },
    chart: [
      { label: "Critical", value: 3, color: "#ff6b6b" },
      { label: "High", value: 8, color: "#ff9f43" },
      { label: "Medium", value: 11, color: "#ffd166" },
      { label: "Low", value: 5, color: "#6ee7a2" },
      { label: "Info", value: 0, color: "#8ab4ff" },
    ],
    findings: [
      { severity: "Critical", title: "Hardcoded Secret", file: "deploy/config.yml", cwe: "CWE-798" },
      { severity: "High", title: "Outdated Dependency", file: "package-lock.json", cwe: "CWE-1104" },
      { severity: "Medium", title: "Missing Security Header", file: "nginx.conf", cwe: "CWE-693" },
    ],
  },
  Management: {
    tone: "exec",
    subtitle: "Board-friendly charts and risk summaries",
    scope: "Shows diagrams, trends, and counts only. No raw evidence, no technical overload, just decision-ready visuals.",
    report: "Executive Summary + Risk Charts",
    tools: ["Summary engine", "Trend aggregation", "Risk scoring"],
    summary: { critical: 3, high: 8, medium: 14, low: 6, info: 0, score: 61.9 },
    chart: [
      { label: "Critical", value: 3, color: "#ff6b6b" },
      { label: "High", value: 8, color: "#ff9f43" },
      { label: "Medium", value: 14, color: "#ffd166" },
      { label: "Low", value: 6, color: "#6ee7a2" },
      { label: "Info", value: 0, color: "#8ab4ff" },
    ],
    findings: [
      { severity: "Critical", title: "Risk Concentration in API Gateway", file: "Executive summary", cwe: "Risk chart" },
      { severity: "High", title: "Open Dependency Exposure", file: "Executive summary", cwe: "Risk chart" },
      { severity: "Medium", title: "Security Hygiene Trend", file: "Executive summary", cwe: "Trend chart" },
    ],
  },
};

const reportTabs = [
  { key: "combined", label: "Combined" },
  { key: "vulnerability", label: "Vulnerability" },
  { key: "fixes", label: "Fixes" },
  { key: "existing", label: "Existing" },
  { key: "management", label: "Management" },
];

function barWidth(value, max) {
  return `${Math.max(8, Math.round((value / max) * 100))}%`;
}

function Chip({ children, active = false, tone = "default", onClick }) {
  return (
    <button className={`chip ${tone} ${active ? "active" : ""}`} onClick={onClick} type="button">
      {children}
    </button>
  );
}

function RoleCard({ role, active, onSelect }) {
  return (
    <button className={`role-card ${active ? "active" : ""}`} type="button" onClick={onSelect}>
      <span className="role-badge">{role}</span>
      <strong>{roles[role].subtitle}</strong>
      <p>{roles[role].report}</p>
    </button>
  );
}

function ReportCard({ title, role, selected }) {
  const data = roles[role];
  return (
    <section className={`report-card ${selected ? "selected" : ""}`}>
      <div className="report-card-head">
        <div>
          <p className="eyebrow">{title}</p>
          <h3>{role}</h3>
        </div>
        <span className={`status ${data.tone}`}>{data.summary.score.toFixed(1)}</span>
      </div>
      <div className="report-grid">
        <div className="report-stat">
          <span>Critical / High</span>
          <strong>
            {data.summary.critical} / {data.summary.high}
          </strong>
        </div>
        <div className="report-stat">
          <span>Scope</span>
          <strong>{data.report}</strong>
        </div>
      </div>
      <div className="mini-bars">
        {data.chart.map((item) => (
          <div key={item.label} className="mini-bar-row">
            <span>{item.label}</span>
            <div className="mini-track">
              <div className="mini-fill" style={{ width: barWidth(item.value, Math.max(...data.chart.map((x) => x.value))), background: item.color }} />
            </div>
            <strong>{item.value}</strong>
          </div>
        ))}
      </div>
    </section>
  );
}

export default function App() {
  const [selectedRole, setSelectedRole] = useState("Management");
  const [selectedReport, setSelectedReport] = useState("combined");

  const roleData = roles[selectedRole];

  const reportSummary = useMemo(() => {
    const type = selectedReport;
    return {
      combined: "Executive view with deduped findings, charts, and drill-down links.",
      vulnerability: "Severity-first analysis with grouped alerts and evidence-by-issue.",
      fixes: "Developer remediation flow with PoC, verification, and fix guidance.",
      existing: "Current control posture with coverage and control verification.",
      management: "Board-friendly charts and trends with no raw evidence overload.",
    }[type];
  }, [selectedReport]);

  return (
    <div className="app-shell">
      <aside className="left-rail">
        <div className="brand">
          <div className="logo-mark">C</div>
          <div>
            <p className="eyebrow">CodeSentinelX Demo</p>
            <h1>Executive Security Console</h1>
          </div>
        </div>

        <div className="rail-panel">
          <p className="section-title">Roles</p>
          <div className="role-list">
            {Object.keys(roles).map((role) => (
              <RoleCard key={role} role={role} active={selectedRole === role} onSelect={() => setSelectedRole(role)} />
            ))}
          </div>
        </div>

        <div className="rail-panel">
          <p className="section-title">Scope</p>
          <p className="rail-copy">{roleData.scope}</p>
          <div className="scope-tags">
            {roleData.tools.map((tool) => (
              <span key={tool}>{tool}</span>
            ))}
          </div>
        </div>
      </aside>

      <main className="main-stage">
        <header className="hero-panel">
          <div>
            <p className="eyebrow">Leadership demo</p>
            <h2>One screen for all role scans and reports</h2>
            <p className="hero-copy">
              Show how CodeSentinelX turns raw scanner output into role-specific, decision-ready reporting for Admin, Security Analyst, Developer, Auditor, and Management.
            </p>
          </div>
          <div className="hero-actions">
            <button type="button" className="primary-btn">Run Demo Scan</button>
            <button type="button" className="secondary-btn">Open Reports</button>
          </div>
        </header>

        <section className="stats-row">
          <article className="stat-panel">
            <span>Selected role</span>
            <strong>{selectedRole}</strong>
          </article>
          <article className="stat-panel">
            <span>Report type</span>
            <strong>{roleData.report}</strong>
          </article>
          <article className="stat-panel">
            <span>Risk score</span>
            <strong>{roleData.summary.score.toFixed(1)}</strong>
          </article>
          <article className="stat-panel">
            <span>Coverage</span>
            <strong>{roleData.summary.critical + roleData.summary.high + roleData.summary.medium + roleData.summary.low + roleData.summary.info}</strong>
          </article>
        </section>

        <section className="content-grid">
          <article className="glass-card execution-card">
            <div className="card-head">
              <div>
                <p className="eyebrow">Execution plan</p>
                <h3>What this role scans</h3>
              </div>
              <Chip tone={roleData.tone}>{selectedRole}</Chip>
            </div>

            <div className="execution-columns">
              <div>
                <p className="section-title">Scope</p>
                <p className="muted">{roleData.scope}</p>
              </div>
              <div>
                <p className="section-title">Tools</p>
                <div className="scope-tags compact">
                  {roleData.tools.map((tool) => (
                    <span key={tool}>{tool}</span>
                  ))}
                </div>
              </div>
              <div>
                <p className="section-title">Report output</p>
                <p className="muted">{roleData.report}</p>
              </div>
            </div>
          </article>

          <article className="glass-card chart-card">
            <div className="card-head">
              <div>
                <p className="eyebrow">Risk summary</p>
                <h3>Severity distribution</h3>
              </div>
              <span className="status">{roleData.summary.score.toFixed(1)}</span>
            </div>
            <div className="severity-bars">
              {roleData.chart.map((item) => {
                const max = Math.max(...roleData.chart.map((entry) => entry.value)) || 1;
                return (
                  <div key={item.label} className="severity-row">
                    <span>{item.label}</span>
                    <div className="track">
                      <div className="fill" style={{ width: barWidth(item.value, max), background: item.color }} />
                    </div>
                    <strong>{item.value}</strong>
                  </div>
                );
              })}
            </div>
          </article>
        </section>

        <section className="glass-card reports-card">
          <div className="card-head">
            <div>
              <p className="eyebrow">Reports</p>
              <h3>Role-aware previews</h3>
            </div>
            <p className="muted">{reportSummary}</p>
          </div>

          <div className="report-tabs">
            {reportTabs.map((tab) => (
              <Chip key={tab.key} active={selectedReport === tab.key} onClick={() => setSelectedReport(tab.key)}>
                {tab.label}
              </Chip>
            ))}
          </div>

          <div className="report-preview">
            <div className="report-summary-panel">
              <p className="eyebrow">Preview</p>
              <h4>{selectedReport === "combined" ? "Combined intelligence view" : `${selectedReport[0].toUpperCase()}${selectedReport.slice(1)} report`}</h4>
              <p className="muted">{reportSummary}</p>
              <div className="findings-list">
                {roleData.findings.map((item, index) => (
                  <div key={`${item.title}-${index}`} className="finding-row">
                    <span className={`sev ${item.severity.toLowerCase()}`}>{item.severity}</span>
                    <div>
                      <strong>{item.title}</strong>
                      <p>{item.file}</p>
                    </div>
                    <span>{item.cwe}</span>
                  </div>
                ))}
              </div>
            </div>

            <div className="report-panels">
              <ReportCard title="Combined" role={selectedRole} selected={selectedReport === "combined"} />
              <ReportCard title="Vulnerability" role={selectedRole} selected={selectedReport === "vulnerability"} />
              <ReportCard title="Fixes" role={selectedRole} selected={selectedReport === "fixes"} />
              <ReportCard title="Existing" role={selectedRole} selected={selectedReport === "existing"} />
              <ReportCard title="Management" role={selectedRole} selected={selectedReport === "management"} />
            </div>
          </div>
        </section>
      </main>
    </div>
  );
}
