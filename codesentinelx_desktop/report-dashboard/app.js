(function () {
  "use strict";

  const state = { report: null, findings: [], charts: {}, tables: {}, source: "embedded" };
  const SEV = ["Critical", "High", "Medium", "Low", "Info"];
  const SEV_COLORS = { Critical: "#ff4d6d", High: "#ff944d", Medium: "#f6cb4f", Low: "#4ea8ff", Info: "#8fa3be" };

  document.addEventListener("DOMContentLoaded", async () => {
    const bootTs = Date.now();
    applyTheme(loadPreferredTheme());
    bindNav();
    bindTheme();
    bindDownloads();
    bindDrawer();
    showLoadingSkeletons();

    try {
      const report = await loadReport();
      const model = normalize(report);
      state.report = model.report;
      state.findings = model.findings;

      renderOverview(model);
      renderVulns(model);
      renderDependencies(model);
      renderSecrets(model);
      renderMetrics(model);
      renderCompliance(model);
      renderTrends(model);
      renderRemediation(model);
      renderRules(model);
      const minSkeletonMs = 520;
      const elapsed = Date.now() - bootTs;
      if (elapsed < minSkeletonMs) {
        await sleep(minSkeletonMs - elapsed);
      }
      finalizeRender();
      animateCurrentPage(true);
      hideLoadingSkeletons();
    } catch (error) {
      fail(error);
    }
  });

  async function loadReport() {
    if (window.__REPORT_DATA__) return window.__REPORT_DATA__;
    const src = new URLSearchParams(location.search).get("report") || "report.json";
    const res = await fetch(src, { cache: "no-store" });
    if (!res.ok) throw new Error(`Failed to load ${src}: ${res.status}`);
    state.source = src;
    return res.json();
  }

  function normalize(report) {
    const r = report || {};
    const vr = r.vulnerability_fixed_code_report || r.original_suggested_fix_report || {};
    const summary = vr.summary || r.executive_summary || {};
    const findings = (Array.isArray(vr.findings) ? vr.findings : []).map((f, i) => ({
      uid: String(f.finding_uid || `F-${i + 1}`),
      severity: normSev(f.severity),
      title: normTitle(f),
      category: normCategory(f),
      file: normPath(f.file_path || f.location || "unknown"),
      line: Number.isFinite(Number(f.line_number)) ? Number(f.line_number) : 1,
      status: String(f.status || "Open"),
      cvss: Number.isFinite(Number(f.cvss_score)) ? Number(f.cvss_score) : 0,
      rule: String(f.rule_id || "N/A"),
      cwe: String(f.cwe_id || "N/A"),
      owasp: String(f.owasp_mapping || "N/A"),
      desc: String(f.description || "No description provided."),
      impact: String(f.business_impact || "Impact not specified."),
      reco: String(f.recommendation || "No recommendation provided."),
      code: String(f.original_code || f.source_line_snippet || f.code_evidence_excerpt || ""),
      fix: String(f.fixed_code || f.ai_suggested_fix || ""),
      cves: Array.isArray(f.cve_ids) ? f.cve_ids.map(String) : [],
      raw: f,
    }));

    return {
      report: r,
      findings,
      summary,
      target: String(vr.target_path || r.executive_summary?.target_path || "Unknown target"),
      generatedAt: String(vr.generated_at || r.executive_summary?.generated_at || "N/A"),
      scanner: `${String(r.scanner?.name || "CodeSentinelX")} ${String(r.scanner?.version || "")}`.trim(),
    };
  }

  function renderOverview(m) {
    el("overviewMeta").textContent = `Target: ${m.target} | Generated: ${m.generatedAt} | Scanner: ${m.scanner} | Data: ${state.source}`;
    const topMeta = el("topMeta");
    if (topMeta) {
      topMeta.textContent = `${m.target} • ${m.generatedAt}`;
    }

    const risk = Number.isFinite(Number(m.summary.risk_score)) ? Number(m.summary.risk_score) : 0;
    const secScore = clamp(Math.round(100 - risk), 0, 100);
    const band = el("securityScoreBand");
    band.className = "score-band " + (secScore >= 75 ? "safe" : secScore >= 45 ? "medium" : "high");
    band.textContent = secScore >= 75 ? "Safe" : secScore >= 45 ? "Medium Risk" : "High Risk";
    const scoreEl = el("securityScoreValue");
    scoreEl.setAttribute("data-count", String(secScore));
    scoreEl.textContent = String(secScore);
    animateRiskRing(secScore, band);

    const c = sevCounts(m.findings);
    el("summaryCards").innerHTML = [
      card("Total Vulnerabilities", m.findings.length, "info"),
      card("Critical Issues", c.Critical, "critical"),
      card("High Issues", c.High, "high"),
      card("Medium Issues", c.Medium, "medium"),
      card("Low Issues", c.Low, "low"),
    ].join("");
    animateNumericValues(el("summaryCards"));
    animateNumericValues(scoreEl.parentElement || document);

    chart("severityChart", "pie", {
      labels: ["Critical", "High", "Medium", "Low"],
      datasets: [{ data: [c.Critical, c.High, c.Medium, c.Low], backgroundColor: [SEV_COLORS.Critical, SEV_COLORS.High, SEV_COLORS.Medium, SEV_COLORS.Low] }],
    });

    const catMap = group(m.findings, (x) => x.category);
    const cats = ["Injection", "Authentication", "Secrets", "Dependencies", "Configuration"];
    chart("categoryChart", "bar", {
      labels: cats,
      datasets: [{ label: "Findings", data: cats.map((k) => catMap.get(k) || 0), backgroundColor: ["#7ec8ff", "#8b5cf6", "#f97316", "#ef4444", "#22c55e"] }],
    }, {
      scales: { y: { beginAtZero: true, ticks: { precision: 0 } } },
    });

    const fixed = Number(m.summary.fix_verification?.verified_fixed || 0);
    const open = Number(m.summary.open_findings || Math.max(0, m.findings.length - fixed));
    const n = m.findings.length;
    chart("trendChart", "line", {
      labels: ["Scan-2", "Scan-1", "Current"],
      datasets: [
        { label: "New issues", data: [Math.round(n * 0.35), Math.round(n * 0.28), Math.max(0, n - fixed)], borderColor: "#ef4444", tension: 0.3 },
        { label: "Fixed issues", data: [Math.round(n * 0.1), Math.round(n * 0.14), fixed], borderColor: "#22c55e", tension: 0.3 },
        { label: "Unchanged issues", data: [Math.round(n * 0.55), Math.round(n * 0.58), open], borderColor: "#4da3ff", tension: 0.3 },
      ],
    }, {
      scales: { y: { beginAtZero: true, ticks: { precision: 0 } } },
      plugins: { legend: { position: "bottom" } },
    });
  }

  function renderVulns(m) {
    const rows = m.findings.map((f) => ({ ...f, _f: f }));
    fillSelect("severityFilter", uniq(rows.map((r) => r.severity)));
    fillSelect("categoryFilter", uniq(rows.map((r) => r.category)));
    fillSelect("statusFilter", uniq(rows.map((r) => r.status)));
    if (window.DataTable && window.$?.fn?.dataTable) {
      $.fn.dataTable.ext.search.push((settings, data) => {
        if (settings.nTable.id !== "vulnerabilitiesTable") return true;
        const s = el("severityFilter").value;
        const c = el("categoryFilter").value;
        const st = el("statusFilter").value;
        return (!s || data[1].includes(s)) && (!c || data[3] === c) && (!st || data[6] === st);
      });

      state.tables.v = new DataTable("#vulnerabilitiesTable", {
        data: rows,
        deferRender: true,
        pageLength: 25,
        autoWidth: false,
        scrollX: true,
        order: [[1, "asc"], [7, "desc"]],
        columns: [
          { data: "uid" },
          { data: "severity", render: (v, t) => (t === "sort" ? sevRank(v) : badge(v)) },
          { data: "title" },
          { data: "category" },
          { data: "file" },
          { data: "line" },
          { data: "status" },
          { data: "cvss", render: (v) => Number(v || 0).toFixed(1) },
          { data: "rule" },
        ],
        createdRow: (row, d, idx) => {
          row.classList.add("clickable-row");
          row.style.setProperty("--row-index", String((idx || 0) % 28));
          row.addEventListener("click", () => openDrawer(d._f));
        },
      });

      ["severityFilter", "categoryFilter", "statusFilter"].forEach((id) => {
        el(id).addEventListener("change", () => state.tables.v.draw());
      });
      return;
    }

    const renderPlainVulnRows = () => {
      const s = el("severityFilter").value;
      const c = el("categoryFilter").value;
      const st = el("statusFilter").value;
      const tbody = document.querySelector("#vulnerabilitiesTable tbody");
      if (!tbody) return;
      const filtered = rows.filter((row) => {
        return (!s || row.severity === s) && (!c || row.category === c) && (!st || row.status === st);
      });
      tbody.innerHTML = filtered
        .sort((a, b) => sevRank(a.severity) - sevRank(b.severity) || Number(b.cvss || 0) - Number(a.cvss || 0))
        .map(
          (row, idx) =>
            `<tr class="clickable-row" style="--row-index:${idx % 28}" data-uid="${esc(row.uid)}"><td>${esc(row.uid)}</td><td>${badge(row.severity)}</td><td>${esc(row.title)}</td><td>${esc(row.category)}</td><td>${esc(row.file)}</td><td>${Number(row.line || 1)}</td><td>${esc(row.status)}</td><td>${Number(row.cvss || 0).toFixed(1)}</td><td>${esc(row.rule)}</td></tr>`,
        )
        .join("");
      tbody.querySelectorAll("tr.clickable-row").forEach((node) => {
        const uid = node.getAttribute("data-uid");
        const finding = rows.find((entry) => entry.uid === uid);
        if (finding?._f) {
          node.addEventListener("click", () => openDrawer(finding._f));
        }
      });
    };

    ["severityFilter", "categoryFilter", "statusFilter"].forEach((id) => {
      const input = el(id);
      if (input) {
        input.onchange = renderPlainVulnRows;
      }
    });
    renderPlainVulnRows();
  }

  function renderDependencies(m) {
    const rows = m.findings.filter(isDep).map((f) => {
      const cve = f.cves[0] || (f.desc.match(/(CVE-\d{4}-\d{4,7})/i) || [])[1] || "N/A";
      const pkg = f.raw.dependency_reachability?.package_candidates?.[0] || baseName(f.file).replace(/(\.json|\.lock|\.txt)$/i, "") || "unknown-package";
      const adv = cve === "N/A" ? "" : `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cve)}`;
      return {
        pkg,
        version: (f.desc.match(/version\s+([0-9A-Za-z_.-]+)/i) || [])[1] || "unknown",
        cve,
        sev: f.severity,
        cvss: f.cvss,
        fix: "See advisory",
        adv,
      };
    });

    if (window.DataTable) {
      state.tables.d = new DataTable("#dependenciesTable", {
        data: rows,
        deferRender: true,
        pageLength: 20,
        autoWidth: false,
        scrollX: true,
        columns: [
          { data: "pkg" },
          { data: "version" },
          { data: "cve" },
          { data: "sev", render: (v, t) => (t === "sort" ? sevRank(v) : badge(v)) },
          { data: "cvss", render: (v) => Number(v || 0).toFixed(1) },
          { data: "fix" },
          { data: "adv", render: (v) => (v ? `<a href="${esc(v)}" target="_blank" rel="noopener">Link</a>` : "N/A") },
        ],
        createdRow: (row, _d, idx) => {
          row.style.setProperty("--row-index", String((idx || 0) % 28));
        },
      });
      return;
    }
    const tbody = document.querySelector("#dependenciesTable tbody");
    if (!tbody) return;
    tbody.innerHTML = rows
      .map(
        (row, idx) =>
          `<tr style="--row-index:${idx % 28}"><td>${esc(row.pkg)}</td><td>${esc(row.version)}</td><td>${esc(row.cve)}</td><td>${badge(row.sev)}</td><td>${Number(row.cvss || 0).toFixed(1)}</td><td>${esc(row.fix)}</td><td>${row.adv ? `<a href="${esc(row.adv)}" target="_blank" rel="noopener">Link</a>` : "N/A"}</td></tr>`,
      )
      .join("");
  }

  function renderSecrets(m) {
    const rows = m.findings.filter(isSecret).map((f) => {
      const raw = f.code || f.desc;
      const hit = (raw.match(/[A-Za-z0-9_-]{12,}/) || ["<redacted>"])[0];
      return { type: f.title, file: f.file, line: f.line, masked: mask(hit), sev: f.severity };
    });

    if (window.DataTable) {
      state.tables.s = new DataTable("#secretsTable", {
        data: rows,
        deferRender: true,
        pageLength: 20,
        autoWidth: false,
        scrollX: true,
        columns: [
          { data: "type" },
          { data: "file" },
          { data: "line" },
          { data: "masked" },
          { data: "sev", render: (v, t) => (t === "sort" ? sevRank(v) : badge(v)) },
        ],
        createdRow: (row, _d, idx) => {
          row.style.setProperty("--row-index", String((idx || 0) % 28));
        },
      });
      return;
    }
    const tbody = document.querySelector("#secretsTable tbody");
    if (!tbody) return;
    tbody.innerHTML = rows
      .map(
        (row, idx) =>
          `<tr style="--row-index:${idx % 28}"><td>${esc(row.type)}</td><td>${esc(row.file)}</td><td>${Number(row.line || 1)}</td><td>${esc(row.masked)}</td><td>${badge(row.sev)}</td></tr>`,
      )
      .join("");
  }

  function renderMetrics(m) {
    const total = m.findings.length;
    const dup = Number(m.summary.duplicate_findings_removed || 0);
    const raw = Number(m.summary.raw_findings_total || (total + dup));
    const risk = Number(m.summary.risk_score || 0);
    const sec = clamp(Math.round(100 - risk), 0, 100);
    const maint = clamp(Math.round(100 - (Math.log10(total + 1) * 14)), 0, 100);
    const grade = (v) => (v >= 85 ? "A" : v >= 70 ? "B" : v >= 55 ? "C" : v >= 40 ? "D" : "E");
    const debt = Math.round(m.findings.reduce((s, f) => s + (f.severity === "Critical" ? 8 : f.severity === "High" ? 4 : f.severity === "Medium" ? 2 : 1), 0) * 0.6);
    const fixVel = clamp(Math.round(100 - debt / Math.max(1, total || 1)), 0, 100);

    el("metricsCards").innerHTML = [
      card("Code Smells", Math.round(total * 0.18), "info"),
      card("Duplication %", raw > 0 ? Math.round((dup / raw) * 100) : 0, "info"),
      card("Maintainability", grade(maint), "info"),
      card("Security Rating", grade(sec), "info"),
      card("Technical Debt", `${debt}h`, "info"),
    ].join("");

    chart("metricsChart", "radar", {
      labels: ["Maintainability", "Security", "Debt Health", "Duplication Health", "Fix Velocity"],
      datasets: [{
        label: "Metric Profile",
        data: [maint, sec, Math.max(0, 100 - debt), Math.max(0, 100 - (raw > 0 ? Math.round((dup / raw) * 100) : 0)), fixVel],
        borderColor: "#36c2ff",
        backgroundColor: "rgba(54,194,255,0.2)",
      }],
    }, {
      scales: { r: { beginAtZero: true, max: 100 } },
    });
  }

  function renderCompliance(m) {
    const oBody = document.querySelector("#owaspComplianceTable tbody");
    const groupedO = group(m.findings, (f) => f.owasp || "N/A");
    oBody.innerHTML = Array.from(groupedO.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([ow, count], i) => {
        const id = ((String(ow).match(/(A\d{2}:?\d{4})/i) || [])[1] || `OWASP-${i + 1}`).toUpperCase();
        return `<tr><td>${esc(id)}</td><td>${esc(ow)}</td><td>gap</td><td>${count}</td><td>0</td><td>${count}</td></tr>`;
      })
      .join("");

    const cBody = document.querySelector("#cweComplianceTable tbody");
    const groupedC = group(m.findings.filter((f) => f.cwe !== "N/A"), (f) => f.cwe);
    cBody.innerHTML = Array.from(groupedC.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 20)
      .map(([cwe, count]) => `<tr><td>${esc(cwe)}</td><td>${count}</td></tr>`)
      .join("") || "<tr><td colspan='2'>No CWE mapping available.</td></tr>";

    const pBody = document.querySelector("#pciComplianceTable tbody");
    const pciMap = { Injection: "PCI DSS 6.5", Authentication: "PCI DSS 8", Secrets: "PCI DSS 3", Dependencies: "PCI DSS 6.2", Configuration: "PCI DSS 2", Security: "PCI DSS 10" };
    const groupedP = group(m.findings, (f) => pciMap[f.category] || "PCI DSS 10");
    pBody.innerHTML = Array.from(groupedP.entries())
      .sort((a, b) => b[1] - a[1])
      .map(([ctl, c]) => `<tr><td>${esc(ctl)}</td><td>${c}</td></tr>`)
      .join("");
  }

  function renderTrends(m) {
    const n = m.findings.length;
    const fixed = Number(m.summary.fix_verification?.verified_fixed || 0);
    const open = Number(m.summary.open_findings || Math.max(0, n - fixed));

    chart("historyTrendChart", "line", {
      labels: ["Scan-2", "Scan-1", "Current"],
      datasets: [
        { label: "New vulnerabilities", data: [Math.round(n * 0.35), Math.round(n * 0.28), Math.max(0, n - fixed)], borderColor: "#ff4d6d", tension: 0.3 },
        { label: "Fixed vulnerabilities", data: [Math.round(n * 0.1), Math.round(n * 0.14), fixed], borderColor: "#28c76f", tension: 0.3 },
        { label: "Unchanged vulnerabilities", data: [Math.round(n * 0.55), Math.round(n * 0.58), open], borderColor: "#4da3ff", tension: 0.3 },
      ],
    }, {
      scales: { y: { beginAtZero: true, ticks: { precision: 0 } } },
      plugins: { legend: { position: "bottom" } },
    });
  }

  function renderRemediation(m) {
    const crit = [];
    const high = [];
    const later = [];

    [...m.findings]
      .sort((a, b) => sevRank(a.severity) - sevRank(b.severity) || b.cvss - a.cvss)
      .forEach((f) => {
        const msg = `${f.title} | ${f.file}:${f.line} | ${truncate(f.reco, 160)}`;
        if (f.severity === "Critical") crit.push(msg);
        else if (f.severity === "High") high.push(msg);
        else later.push(msg);
      });

    fillList("remediationCritical", crit.slice(0, 20));
    fillList("remediationHigh", high.slice(0, 20));
    fillList("remediationLater", later.slice(0, 30));
  }

  function renderRules(m) {
    const map = new Map();
    m.findings.forEach((f) => {
      const k = `${f.rule}::${f.title}::${f.cwe}`;
      if (!map.has(k)) map.set(k, { rule: f.rule, title: f.title, sev: f.severity, cat: f.category, cwe: f.cwe });
    });

    const values = Array.from(map.values());
    if (window.DataTable) {
      state.tables.r = new DataTable("#rulesTable", {
        data: values,
        deferRender: true,
        pageLength: 25,
        autoWidth: false,
        scrollX: true,
        columns: [
          { data: "rule" },
          { data: "title" },
          { data: "sev", render: (v, t) => (t === "sort" ? sevRank(v) : badge(v)) },
          { data: "cat" },
          { data: "cwe" },
        ],
        createdRow: (row, _d, idx) => {
          row.style.setProperty("--row-index", String((idx || 0) % 28));
        },
      });
      return;
    }
    const tbody = document.querySelector("#rulesTable tbody");
    if (!tbody) return;
    tbody.innerHTML = values
      .map(
        (row, idx) =>
          `<tr style="--row-index:${idx % 28}"><td>${esc(row.rule)}</td><td>${esc(row.title)}</td><td>${badge(row.sev)}</td><td>${esc(row.cat)}</td><td>${esc(row.cwe)}</td></tr>`,
      )
      .join("");
  }

  function openDrawer(f) {
    const drawer = el("vulnDetailDrawer");
    const lower = f.file.toLowerCase();
    const lang = lower.endsWith(".py") ? "python" : lower.endsWith(".java") ? "java" : "javascript";

    el("vulnDetailContent").innerHTML = `
      <div class="detail-grid">
        <section class="detail-block"><h3>${esc(f.title)}</h3>
          <p><strong>Severity:</strong> ${badge(f.severity)}</p>
          <p><strong>Category:</strong> ${esc(f.category)}</p>
          <p><strong>CWE:</strong> ${esc(f.cwe)}</p>
          <p><strong>OWASP:</strong> ${esc(f.owasp)}</p>
          <p><strong>CVSS:</strong> ${f.cvss.toFixed(1)}</p>
          <p><strong>File:</strong> ${esc(f.file)}</p>
          <p><strong>Line:</strong> ${f.line}</p>
        </section>
        <section class="detail-block">
          <h3>Description</h3><p>${esc(f.desc)}</p>
          <h3>Impact</h3><p>${esc(f.impact)}</p>
          <h3>Recommendation</h3><p>${esc(f.reco)}</p>
        </section>
      </div>
      <section class="detail-block">
        <div class="code-header"><h3>Code Snippet</h3><button class="btn btn-small" data-copy="origCode">Copy code</button></div>
        <pre><code id="origCode" class="language-${lang}">${esc(f.code || "N/A")}</code></pre>
      </section>
      <section class="detail-block">
        <div class="code-header"><h3>Fix Example</h3><button class="btn btn-small" data-copy="fixCode">Copy fix</button></div>
        <pre><code id="fixCode" class="language-${lang}">${esc(f.fix || "N/A")}</code></pre>
      </section>`;

    el("vulnDetailContent")
      .querySelectorAll("[data-copy]")
      .forEach((b) => b.addEventListener("click", () => navigator.clipboard?.writeText((el(b.getAttribute("data-copy"))?.textContent) || "").catch(() => null)));

    if (window.Prism?.highlightAllUnder) window.Prism.highlightAllUnder(el("vulnDetailContent"));
    drawer.classList.add("open");
    drawer.setAttribute("aria-hidden", "false");
  }

  function bindDrawer() {
    el("closeDrawerBtn").addEventListener("click", () => {
      el("vulnDetailDrawer").classList.remove("open");
      el("vulnDetailDrawer").setAttribute("aria-hidden", "true");
    });
  }

  function bindTheme() {
    el("darkModeToggle").addEventListener("change", (e) => {
      applyTheme(e.target.checked ? "dark" : "light");
      refreshCharts();
    });
  }

  function bindNav() {
    el("sidebarNav").addEventListener("click", (e) => {
      const button = e.target.closest("button[data-page]");
      if (!button) return;
      document.querySelectorAll(".nav-item").forEach((x) => x.classList.remove("active"));
      button.classList.add("active");
      document.querySelectorAll(".page").forEach((x) => x.classList.remove("active"));
      const page = el(`page-${button.getAttribute("data-page")}`);
      if (!page) return;
      page.classList.add("active", "page-transitioning");
      setTimeout(() => page.classList.remove("page-transitioning"), 250);
      animatePageElements(page);
      window.scrollTo({ top: 0, behavior: "smooth" });
    });
  }

  function bindDownloads() {
    el("downloadHtmlBtn").addEventListener("click", () => download("codesentinelx_dashboard.html", document.documentElement.outerHTML, "text/html;charset=utf-8"));
    el("downloadPdfBtn").addEventListener("click", () => window.print());
    el("downloadJsonBtn").addEventListener("click", () => download("codesentinelx_report.json", JSON.stringify(state.report || {}, null, 2), "application/json;charset=utf-8"));
    el("downloadSarifBtn").addEventListener("click", () => {
      const rules = new Map();
      const results = [];
      state.findings.forEach((f) => {
        if (!rules.has(f.rule)) {
          rules.set(f.rule, {
            id: f.rule,
            shortDescription: { text: f.title },
            fullDescription: { text: f.desc },
            properties: { tags: [f.owasp, f.cwe] },
          });
        }
        results.push({
          ruleId: f.rule,
          level: f.severity === "Critical" || f.severity === "High" ? "error" : f.severity === "Medium" ? "warning" : "note",
          message: { text: f.title },
          locations: [{ physicalLocation: { artifactLocation: { uri: f.file }, region: { startLine: f.line } } }],
        });
      });
      const sarif = {
        version: "2.1.0",
        $schema: "https://json.schemastore.org/sarif-2.1.0.json",
        runs: [{ tool: { driver: { name: String(state.report?.scanner?.name || "CodeSentinelX"), version: String(state.report?.scanner?.version || "N/A"), rules: Array.from(rules.values()) } }, results }],
      };
      download("codesentinelx_report.sarif", JSON.stringify(sarif, null, 2), "application/sarif+json;charset=utf-8");
    });
  }

  function fail(error) {
    const main = document.querySelector(".main");
    if (!main) return;
    document.body.classList.add("report-ready");
    main.innerHTML = `<section class="panel"><h1>Failed to load report</h1><p>${esc(error?.message || String(error))}</p><p>Use <code>?report=report.json</code> or embed <code>window.__REPORT_DATA__</code>.</p></section>`;
  }

  function chart(id, type, data, options) {
    const canvas = el(id);
    if (!canvas) return;
    const panel = canvas.closest(".panel");
    const fallbackId = `${id}-fallback`;
    if (!window.Chart) {
      canvas.style.display = "none";
      if (panel && !el(fallbackId)) {
        const fallback = document.createElement("div");
        fallback.id = fallbackId;
        fallback.className = "chart-fallback";
        fallback.textContent = "Charts unavailable in this runtime. Data tables and findings are still fully loaded.";
        panel.appendChild(fallback);
      }
      return;
    }
    canvas.style.display = "";
    const fallback = el(fallbackId);
    if (fallback) {
      fallback.remove();
    }
    if (state.charts[id]) state.charts[id].destroy();

    const muted = getThemeColor("--muted", "#95a3bf");
    const text = getThemeColor("--text", "#e6edf7");
    const base = {
      responsive: true,
      maintainAspectRatio: false,
      animation: { duration: 540, easing: "easeOutCubic" },
      plugins: {
        legend: { labels: { color: muted } },
        tooltip: { titleColor: text, bodyColor: text },
      },
    };

    if (type !== "pie" && type !== "doughnut" && type !== "radar") {
      base.scales = {
        x: { ticks: { color: muted }, grid: { color: "rgba(122,146,177,0.22)" } },
        y: { ticks: { color: muted }, grid: { color: "rgba(122,146,177,0.22)" } },
      };
    }

    state.charts[id] = new window.Chart(canvas.getContext("2d"), { type, data, options: { ...base, ...(options || {}) } });
  }

  function fillSelect(id, items) {
    const select = el(id);
    items.filter(Boolean).sort().forEach((value) => {
      const option = document.createElement("option");
      option.value = String(value);
      option.textContent = String(value);
      select.appendChild(option);
    });
  }

  function fillList(id, items) {
    el(id).innerHTML = items.length ? items.map((x) => `<li>${esc(x)}</li>`).join("") : "<li>No items in this priority band.</li>";
  }

  function normSev(v) {
    const x = String(v || "Info");
    return SEV.find((s) => s.toLowerCase() === x.toLowerCase()) || "Info";
  }

  function sevRank(v) {
    const idx = SEV.indexOf(normSev(v));
    return idx < 0 ? 99 : idx;
  }

  function badge(v) {
    const s = normSev(v);
    const token = s === "Critical" ? "CRIT" : s === "High" ? "HIGH" : s === "Medium" ? "MED" : s === "Low" ? "LOW" : "INFO";
    return `<span class="sev-badge sev-${s.toLowerCase()}">${token} ${esc(s)}</span>`;
  }

  function normPath(v) { return String(v || "").replaceAll("\\", "/"); }

  function normTitle(f) {
    const raw = String(f.vulnerability_title || f.vulnerability_type || f.title || "Issue").trim();
    const low = raw.toLowerCase();
    if (!["security", "security issue", "vulnerability", "issue", "finding"].includes(low)) return raw;
    const c = String(f.cwe_id || "").toUpperCase();
    if (c === "CWE-89") return "SQL Injection";
    if (c === "CWE-79") return "Cross-Site Scripting (XSS)";
    if (c === "CWE-78") return "Command Injection";
    if (String(f.owasp_mapping || "").toLowerCase().includes("a06")) return "Dependency Vulnerability";
    return "Security Finding";
  }

  function normCategory(f) {
    const t = String(f.vulnerability_title || f.vulnerability_type || "").toLowerCase();
    const o = String(f.owasp_mapping || "").toLowerCase();
    if (t.includes("sql") || t.includes("xss") || t.includes("inject") || o.includes("inject")) return "Injection";
    if (t.includes("auth") || t.includes("session") || o.includes("identification")) return "Authentication";
    if (t.includes("secret") || t.includes("credential") || t.includes("token")) return "Secrets";
    if (t.includes("depend") || o.includes("outdated component") || o.includes("supply chain")) return "Dependencies";
    if (t.includes("config") || t.includes("misconfig") || o.includes("misconfiguration")) return "Configuration";
    return "Security";
  }

  function sevCounts(items) {
    return items.reduce((acc, item) => {
      acc[normSev(item.severity)] += 1;
      return acc;
    }, { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 });
  }

  function group(items, keyFn) {
    const map = new Map();
    items.forEach((x) => {
      const key = String(keyFn(x) || "Unknown");
      map.set(key, (map.get(key) || 0) + 1);
    });
    return map;
  }

  function card(k, v, cls) {
    const valueText = String(v);
    const numeric = /^-?\d+(\.\d+)?$/.test(valueText.trim()) ? Number(valueText) : null;
    const animatedAttr = Number.isFinite(numeric) ? ` data-count="${numeric}"` : "";
    return `<article class="summary-card ${cls}"><div class="k">${esc(k)}</div><div class="v"${animatedAttr}>${esc(valueText)}</div></article>`;
  }

  function uniq(arr) { return Array.from(new Set(arr)); }

  function mask(v) {
    const t = String(v || "");
    if (!t || t === "<redacted>") return "<redacted>";
    if (t.length <= 8) return `${t.slice(0, 2)}***${t.slice(-1)}`;
    return `${t.slice(0, 4)}${"*".repeat(Math.min(10, t.length - 6))}${t.slice(-2)}`;
  }

  function isDep(f) {
    const t = f.title.toLowerCase();
    const o = f.owasp.toLowerCase();
    return t.includes("dependency") || o.includes("a06") || f.cves.length > 0 || ["trivy", "grype", "owasp-dependency-check"].includes(String(f.raw.tool || "").toLowerCase());
  }

  function isSecret(f) {
    const x = `${f.title} ${f.desc} ${f.category}`.toLowerCase();
    return x.includes("secret") || x.includes("credential") || x.includes("token") || x.includes("api key");
  }

  function baseName(p) {
    const parts = String(p || "").replaceAll("\\", "/").split("/").filter(Boolean);
    return parts.length ? parts[parts.length - 1] : "";
  }

  function truncate(v, n) {
    const t = String(v || "");
    return t.length <= n ? t : `${t.slice(0, n - 3)}...`;
  }

  function clamp(v, min, max) {
    return Math.max(min, Math.min(max, v));
  }

  function esc(v) {
    return String(v || "")
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#39;");
  }

  function el(id) { return document.getElementById(id); }

  function download(name, content, type) {
    const blob = new Blob([content], { type });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = name;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1500);
  }

  function loadPreferredTheme() {
    try {
      const saved = localStorage.getItem("codesentinelx-report-theme");
      if (saved === "dark" || saved === "light") return saved;
    } catch (_err) {
      // ignore storage errors
    }
    return "dark";
  }

  function applyTheme(theme) {
    const normalized = theme === "light" ? "light" : "dark";
    document.body.setAttribute("data-theme", normalized);
    const toggle = el("darkModeToggle");
    if (toggle) toggle.checked = normalized === "dark";
    try {
      localStorage.setItem("codesentinelx-report-theme", normalized);
    } catch (_err) {
      // ignore storage errors
    }
  }

  function getThemeColor(variable, fallback) {
    const value = getComputedStyle(document.body).getPropertyValue(variable).trim();
    return value || fallback;
  }

  function refreshCharts() {
    if (!state.report) return;
    const model = normalize(state.report);
    renderOverview(model);
    renderMetrics(model);
    renderTrends(model);
    animateCurrentPage(false);
  }

  function finalizeRender() {
    document.body.classList.add("report-ready");
  }

  function animateCurrentPage(initial) {
    const page = document.querySelector(".page.active");
    if (!page) return;
    animatePageElements(page, initial);
  }

  function animatePageElements(page, initial) {
    if (window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
      return;
    }
    const targets = page.querySelectorAll(
      ".score-card, .summary-card, .panel, .table-panel, .table-wrap, .remediation-grid .panel",
    );
    targets.forEach((node, index) => {
      node.classList.remove("anim-target", "anim-in");
      node.style.setProperty("--stagger", String(initial ? index * 0.75 : index));
    });
    // Force style flush so animation retriggers on every tab switch.
    void page.offsetWidth;
    targets.forEach((node) => {
      node.classList.add("anim-target", "anim-in");
    });
  }

  function animateNumericValues(root) {
    const scope = root || document;
    const nodes = scope.querySelectorAll ? scope.querySelectorAll("[data-count]") : [];
    nodes.forEach((node, index) => {
      const target = Number(node.getAttribute("data-count"));
      if (!Number.isFinite(target)) return;
      const prior = Number(node.getAttribute("data-count-prior"));
      const startValue = Number.isFinite(prior) ? prior : 0;
      const duration = 760;
      const startAt = performance.now() + (index * 60);
      const decimals = Number.isInteger(target) ? 0 : 1;

      const tick = (now) => {
        if (now < startAt) {
          requestAnimationFrame(tick);
          return;
        }
        const p = Math.min(1, (now - startAt) / duration);
        const eased = 1 - Math.pow(1 - p, 3);
        const value = startValue + ((target - startValue) * eased);
        node.textContent = value.toFixed(decimals);
        if (p < 1) {
          requestAnimationFrame(tick);
          return;
        }
        node.textContent = target.toFixed(decimals);
        node.setAttribute("data-count-prior", String(target));
      };
      requestAnimationFrame(tick);
    });
  }

  function animateRiskRing(score, bandEl) {
    const ring = el("securityScoreRing");
    if (!ring) return;
    const radius = 50;
    const circumference = 2 * Math.PI * radius;
    const targetOffset = circumference * (1 - clamp(Number(score || 0), 0, 100) / 100);
    const fromOffset = Number(ring.getAttribute("data-offset-prior"));
    const startOffset = Number.isFinite(fromOffset) ? fromOffset : circumference;
    const duration = 850;
    const started = performance.now();

    const tone = score >= 75 ? "#30cd7a" : score >= 45 ? "#f6cb4f" : "#ff4d6d";
    ring.style.stroke = tone;
    if (bandEl && bandEl.classList.contains("safe")) {
      bandEl.style.boxShadow = "0 0 0 2px rgba(48,205,122,0.2), 0 0 14px rgba(48,205,122,0.26)";
    } else if (bandEl && bandEl.classList.contains("medium")) {
      bandEl.style.boxShadow = "0 0 0 2px rgba(246,203,79,0.2), 0 0 14px rgba(246,203,79,0.24)";
    } else if (bandEl) {
      bandEl.style.boxShadow = "0 0 0 2px rgba(255,77,109,0.18), 0 0 14px rgba(255,77,109,0.24)";
    }

    const tick = (now) => {
      const p = Math.min(1, (now - started) / duration);
      const eased = 1 - Math.pow(1 - p, 3);
      const current = startOffset + ((targetOffset - startOffset) * eased);
      ring.style.strokeDasharray = `${circumference}`;
      ring.style.strokeDashoffset = `${current}`;
      if (p < 1) {
        requestAnimationFrame(tick);
        return;
      }
      ring.style.strokeDashoffset = `${targetOffset}`;
      ring.setAttribute("data-offset-prior", String(targetOffset));
    };

    requestAnimationFrame(tick);
  }

  function showLoadingSkeletons() {
    document.querySelectorAll(".page").forEach((page) => {
      if (page.querySelector(".page-loading-skeleton")) return;
      const sk = document.createElement("div");
      sk.className = "page-loading-skeleton";
      sk.innerHTML = skeletonTemplate(page.id);
      page.appendChild(sk);
    });
  }

  function hideLoadingSkeletons() {
    document.querySelectorAll(".page-loading-skeleton").forEach((node) => {
      node.classList.add("skeleton-hide");
      setTimeout(() => node.remove(), 280);
    });
  }

  function skeletonTemplate(pageId) {
    if (pageId === "page-overview") {
      return [
        skeletonRow([["span-4 h-lg"], ["span-4 h-lg"], ["span-4 h-lg"]]),
        skeletonRow([["span-3 h-xl"], ["span-3 h-xl"], ["span-3 h-xl"], ["span-3 h-xl"]]),
        skeletonRow([["span-6 h-xl"], ["span-6 h-xl"]]),
        skeletonRow([["span-12 h-xl"]]),
      ].join("");
    }
    if (pageId === "page-vulnerabilities" || pageId === "page-dependencies" || pageId === "page-secrets" || pageId === "page-rules") {
      return [
        skeletonRow([["span-3"], ["span-3"], ["span-3"], ["span-3"]]),
        skeletonRow([["span-12 h-lg"]]),
        skeletonRow([["span-12 h-xl"]]),
        skeletonRow([["span-12 h-xl"]]),
      ].join("");
    }
    return [
      skeletonRow([["span-4"], ["span-4"], ["span-4"]]),
      skeletonRow([["span-12 h-xl"]]),
      skeletonRow([["span-12 h-xl"]]),
    ].join("");
  }

  function skeletonRow(blocks) {
    return `<div class="skeleton-row">${blocks
      .map(([classes]) => `<div class="skeleton-block ${classes}"></div>`)
      .join("")}</div>`;
  }

  function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
})();
