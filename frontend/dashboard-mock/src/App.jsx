import { useMemo, useState } from "react";

const summary = {
  project: "payments-service",
  riskScore: 78.4,
  trend: "+6.3%",
  severity: {
    Critical: 4,
    High: 12,
    Medium: 22,
    Low: 14,
    Info: 7,
  },
};

const findingSeed = [
  {
    id: "F-101",
    severity: "Critical",
    title: "SQL Injection in order query",
    file: "src/orders/repository.py",
    line: 88,
    cwe: "CWE-89",
    owasp: "A03:2021 - Injection",
    snippet: "query = \"SELECT * FROM orders WHERE id = \" + order_id",
  },
  {
    id: "F-102",
    severity: "High",
    title: "Hardcoded AWS key",
    file: "config/settings.js",
    line: 14,
    cwe: "CWE-798",
    owasp: "A02:2021 - Cryptographic Failures",
    snippet: "const API_KEY = 'AKIA...';",
  },
  {
    id: "F-103",
    severity: "Medium",
    title: "Weak hash algorithm",
    file: "auth/hash.go",
    line: 44,
    cwe: "CWE-327",
    owasp: "A02:2021 - Cryptographic Failures",
    snippet: "sum := md5.New()",
  },
];

const heatmap = [
  ["auth", 18],
  ["payments", 40],
  ["checkout", 27],
  ["admin", 12],
  ["reporting", 9],
  ["notifications", 6],
];

const severityOrder = ["Critical", "High", "Medium", "Low", "Info"];

function barWidth(value, max) {
  return `${Math.round((value / max) * 100)}%`;
}

function App() {
  const [selectedSeverity, setSelectedSeverity] = useState("All");

  const findings = useMemo(() => {
    if (selectedSeverity === "All") {
      return findingSeed;
    }
    return findingSeed.filter((item) => item.severity === selectedSeverity);
  }, [selectedSeverity]);

  const maxHeat = Math.max(...heatmap.map(([, value]) => value));

  return (
    <div className="page">
      <header className="hero">
        <p className="eyebrow">CodeSentinel X</p>
        <h1>Enterprise Security Intelligence</h1>
        <p>Real-time risk visibility, CWE/CVE mapping, and developer-ready remediation workflows.</p>
      </header>

      <section className="grid top-grid">
        <article className="card stat-card">
          <p>Project</p>
          <h2>{summary.project}</h2>
        </article>
        <article className="card stat-card">
          <p>Risk Score</p>
          <h2>{summary.riskScore}</h2>
        </article>
        <article className="card stat-card">
          <p>Trend (7d)</p>
          <h2>{summary.trend}</h2>
        </article>
      </section>

      <section className="grid mid-grid">
        <article className="card">
          <h3>Severity Distribution</h3>
          <div className="severity-row">
            {severityOrder.map((level) => (
              <button
                key={level}
                className={`pill ${selectedSeverity === level ? "active" : ""}`}
                onClick={() => setSelectedSeverity(level)}
              >
                {level}: {summary.severity[level]}
              </button>
            ))}
            <button className={`pill ${selectedSeverity === "All" ? "active" : ""}`} onClick={() => setSelectedSeverity("All")}>
              All
            </button>
          </div>
        </article>

        <article className="card">
          <h3>Risk Heatmap (Modules)</h3>
          <div className="heatmap">
            {heatmap.map(([module, value]) => (
              <div key={module} className="heat-row">
                <span>{module}</span>
                <div className="heat-track">
                  <div className="heat-bar" style={{ width: barWidth(value, maxHeat) }} />
                </div>
                <strong>{value}</strong>
              </div>
            ))}
          </div>
        </article>
      </section>

      <section className="card">
        <h3>Finding Drill-Down</h3>
        <table>
          <thead>
            <tr>
              <th>Severity</th>
              <th>Title</th>
              <th>File</th>
              <th>Line</th>
              <th>CWE</th>
              <th>OWASP</th>
              <th>Snippet</th>
            </tr>
          </thead>
          <tbody>
            {findings.map((item) => (
              <tr key={item.id}>
                <td><span className={`sev ${item.severity.toLowerCase()}`}>{item.severity}</span></td>
                <td>{item.title}</td>
                <td>{item.file}</td>
                <td>{item.line}</td>
                <td>{item.cwe}</td>
                <td>{item.owasp}</td>
                <td><code>{item.snippet}</code></td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </div>
  );
}

export default App;
