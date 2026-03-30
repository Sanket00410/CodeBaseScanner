const state = {
  scanId: null,
  pollHandle: null,
  report: null,
  currentSeverityFilter: "All",
  searchQuery: "",
  filteredFindings: [],
  selectedFindingKey: null,
  currentReportView: "vulnerability",
};

const elements = {
  form: document.getElementById("scanForm"),
  targetPath: document.getElementById("targetPath"),
  scanButton: document.getElementById("scanButton"),
  scanMessage: document.getElementById("scanMessage"),
  scanStatusMeta: document.getElementById("scanStatusMeta"),
  progressBar: document.getElementById("progressBar"),
  progressText: document.getElementById("progressText"),
  reportSwitch: document.getElementById("reportSwitch"),
  reportTabs: Array.from(document.querySelectorAll(".report-tab[data-view]")),
  dashboardSection: document.getElementById("dashboardSection"),
  findingsSection: document.getElementById("findingsSection"),
  controlsSection: document.getElementById("controlsSection"),
  totalFindings: document.getElementById("totalFindings"),
  dedupFindings: document.getElementById("dedupFindings"),
  dupRemoved: document.getElementById("dupRemoved"),
  riskScore: document.getElementById("riskScore"),
  activeRiskCount: document.getElementById("activeRiskCount"),
  filesImpacted: document.getElementById("filesImpacted"),
  assessmentConfidence: document.getElementById("assessmentConfidence"),
  severityGrid: document.getElementById("severityGrid"),
  owaspTableBody: document.getElementById("owaspTableBody"),
  moduleTableBody: document.getElementById("moduleTableBody"),
  actionPlan: document.getElementById("actionPlan"),
  controlsSummary: document.getElementById("controlsSummary"),
  controlsTableBody: document.getElementById("controlsTableBody"),
  complianceTableBody: document.getElementById("complianceTableBody"),
  toolchainTableBody: document.getElementById("toolchainTableBody"),
  findingsTableBody: document.getElementById("findingsTableBody"),
  filters: document.getElementById("filters"),
  findingSearch: document.getElementById("findingSearch"),
  detailTitle: document.getElementById("detailTitle"),
  detailMeta: document.getElementById("detailMeta"),
  detailImpact: document.getElementById("detailImpact"),
  detailScenario: document.getElementById("detailScenario"),
  detailExploit: document.getElementById("detailExploit"),
  detailPoc: document.getElementById("detailPoc"),
  detailFix: document.getElementById("detailFix"),
  detailSecureExample: document.getElementById("detailSecureExample"),
  detailOriginal: document.getElementById("detailOriginal"),
  detailFixed: document.getElementById("detailFixed"),
  detailPatch: document.getElementById("detailPatch"),
  detailReference: document.getElementById("detailReference"),
  copyFixedCodeBtn: document.getElementById("copyFixedCodeBtn"),
  copyPatchBtn: document.getElementById("copyPatchBtn"),
  railLinks: Array.from(document.querySelectorAll(".rail-link[data-target]")),
  exportButtons: Array.from(document.querySelectorAll(".export-btn")),
};

const severityRank = {
  Critical: 0,
  High: 1,
  Medium: 2,
  Low: 3,
  Info: 4,
};

function escapeHtml(text) {
  return String(text)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function setMessage(message, isError = false) {
  elements.scanMessage.textContent = message;
  elements.scanMessage.classList.toggle("error", isError);
}

function updateProgress(percent) {
  const normalized = Math.max(0, Math.min(100, Number(percent || 0)));
  elements.progressBar.style.width = `${normalized}%`;
  elements.progressText.textContent = `${normalized.toFixed(1)}%`;
}

function enableExportButtons(enabled) {
  elements.exportButtons.forEach((button) => {
    button.disabled = !enabled;
  });
}

async function startScan(targetPath) {
  const response = await fetch("/api/scans", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ target_path: targetPath }),
  });

  if (!response.ok) {
    const payload = await response.json().catch(() => ({ detail: "Unable to start scan" }));
    throw new Error(payload.detail || "Unable to start scan");
  }

  return response.json();
}

async function fetchStatus(scanId) {
  const response = await fetch(`/api/scans/${scanId}`);
  if (!response.ok) {
    throw new Error("Failed to fetch scan status");
  }
  return response.json();
}

async function fetchResults(scanId) {
  const response = await fetch(`/api/scans/${scanId}/results`);
  if (!response.ok) {
    throw new Error("Scan results are not available");
  }
  return response.json();
}

function findingKey(item) {
  return item.finding_uid || `${item.rule_id}::${item.file_path}::${item.line_number}`;
}

function sortedFindings(findings) {
  return [...findings].sort((a, b) => {
    const sa = severityRank[a.severity] ?? 99;
    const sb = severityRank[b.severity] ?? 99;
    if (sa !== sb) {
      return sa - sb;
    }
    const cvssa = Number(a.cvss_score || 0);
    const cvssb = Number(b.cvss_score || 0);
    if (cvssb !== cvssa) {
      return cvssb - cvssa;
    }
    return `${a.file_path}:${a.line_number}`.localeCompare(`${b.file_path}:${b.line_number}`);
  });
}

function activateFilterButton(selectedSeverity) {
  Array.from(elements.filters.querySelectorAll(".filter-btn")).forEach((button) => {
    const active = button.dataset.severity === selectedSeverity;
    button.classList.toggle("active", active);
  });
}

function activateRailLink(targetId) {
  elements.railLinks.forEach((button) => {
    const active = button.dataset.target === targetId;
    button.classList.toggle("active", active);
  });
}

function activateReportTab(view) {
  elements.reportTabs.forEach((button) => {
    button.classList.toggle("active", button.dataset.view === view);
  });
}

function switchReportView(view) {
  state.currentReportView = view;
  activateReportTab(view);

  if (view === "existing") {
    elements.dashboardSection.classList.add("hidden");
    elements.findingsSection.classList.add("hidden");
    elements.controlsSection.classList.remove("hidden");
    activateRailLink("controlsSection");
    return;
  }

  elements.dashboardSection.classList.remove("hidden");
  elements.findingsSection.classList.remove("hidden");
  elements.controlsSection.classList.add("hidden");
  activateRailLink("dashboardSection");
}

function renderSummary(report) {
  const summary = report.executive_summary || {};
  elements.totalFindings.textContent = String(summary.total_vulnerabilities || 0);
  elements.dedupFindings.textContent = String(summary.deduplicated_vulnerabilities || summary.total_vulnerabilities || 0);
  elements.dupRemoved.textContent = String(summary.duplicate_findings_removed || 0);
  elements.riskScore.textContent = `${summary.risk_score || 0} (${summary.risk_rating || "N/A"})`;
  elements.activeRiskCount.textContent = String(summary.active_risk_findings || 0);
  elements.filesImpacted.textContent = String(summary.total_files_impacted || 0);
  elements.assessmentConfidence.textContent = String(summary.assessment_confidence || "N/A");

  const severityCards = Object.entries(summary.severity_distribution || {})
    .map(([severity, count]) => {
      const cssClass = `sev-${severity.toLowerCase()}`;
      return `
        <article class="severity-card ${cssClass}">
          <p>${escapeHtml(severity)}</p>
          <h4>${count}</h4>
        </article>
      `;
    })
    .join("");
  elements.severityGrid.innerHTML = severityCards;

  const owaspRows = (summary.top_owasp_categories || [])
    .map((item) => `<tr><td>${escapeHtml(item.owasp_category)}</td><td>${item.count}</td></tr>`)
    .join("");
  elements.owaspTableBody.innerHTML = owaspRows || "<tr><td colspan='2'>No OWASP mapping available.</td></tr>";

  const moduleRows = (summary.affected_modules || [])
    .map(
      (item) =>
        `<tr><td>${escapeHtml(item.module)}</td><td>${item.count}</td><td>${item.critical}</td><td>${item.high}</td></tr>`
    )
    .join("");
  elements.moduleTableBody.innerHTML = moduleRows || "<tr><td colspan='4'>No module distribution available.</td></tr>";

  const actions = (summary.recommended_action_plan || [])
    .map((item) => `<li>${escapeHtml(item)}</li>`)
    .join("");
  elements.actionPlan.innerHTML = actions;
}

function renderControls(report) {
  const existing = report.existing_implementation_report || {};
  const controlsSummary = existing.summary || {};
  const controls = existing.controls || [];
  const compliance = existing.compliance_matrix || [];

  const implemented = controlsSummary.implemented_controls || controls.length || 0;
  const standardsCount = Object.keys(controlsSummary.standards_coverage || {}).length;
  elements.controlsSummary.textContent =
    `Implemented controls: ${implemented} | Standards covered: ${standardsCount}`;

  const controlsRows = controls
    .map((control) => {
      const standards = (control.standard_mappings || []).join(", ");
      return `
        <tr>
          <td>${escapeHtml(control.name || "Control")}</td>
          <td>${escapeHtml(control.category || "Security")}</td>
          <td>${escapeHtml(control.coverage_level || "N/A")}</td>
          <td>${escapeHtml(standards)}</td>
        </tr>
      `;
    })
    .join("");

  elements.controlsTableBody.innerHTML =
    controlsRows || "<tr><td colspan='4'>No implemented controls detected by current rule catalog.</td></tr>";

  const complianceRows = compliance
    .map(
      (item) => `
        <tr>
          <td>${escapeHtml(item.standard || "N/A")}</td>
          <td>${Number(item.control_count || 0)}</td>
          <td>${escapeHtml(item.status || "partial")}</td>
        </tr>
      `
    )
    .join("");

  elements.complianceTableBody.innerHTML =
    complianceRows || "<tr><td colspan='3'>No compliance matrix data available.</td></tr>";

  const toolchain = (report.vulnerability_fixed_code_report || {}).toolchain_status || {};
  const toolRows = Object.entries(toolchain)
    .map(([tool, status]) => {
      const toolState = status.available ? "Enabled" : "Missing";
      return `
        <tr>
          <td>${escapeHtml(tool)}</td>
          <td>${escapeHtml(toolState)}</td>
          <td>${escapeHtml(status.source || "unknown")}</td>
          <td>${escapeHtml(status.message || "")}</td>
        </tr>
      `;
    })
    .join("");

  elements.toolchainTableBody.innerHTML =
    toolRows || "<tr><td colspan='4'>No external toolchain status available.</td></tr>";
}

function vulnerabilityFindingsFromReport() {
  const vuln = state.report?.vulnerability_fixed_code_report || {};
  const findings = vuln.findings || state.report?.technical_report?.findings || [];
  return Array.isArray(findings) ? findings : [];
}

function getFilteredFindings() {
  const findings = vulnerabilityFindingsFromReport();
  const query = state.searchQuery.trim().toLowerCase();

  return sortedFindings(findings).filter((item) => {
    if (state.currentSeverityFilter !== "All" && item.severity !== state.currentSeverityFilter) {
      return false;
    }

    if (!query) {
      return true;
    }

    const haystack = [
      item.vulnerability_title,
      item.vulnerability_type,
      item.file_path,
      item.cwe_id,
      item.owasp_mapping,
      item.rule_id,
      item.affected_module,
    ]
      .filter(Boolean)
      .join(" ")
      .toLowerCase();

    return haystack.includes(query);
  });
}

function renderFindingDetail(item) {
  if (!item) {
    elements.detailTitle.textContent = "Select a finding";
    elements.detailMeta.textContent = "Severity, location, CWE, OWASP, CVSS";
    elements.detailImpact.textContent = "-";
    elements.detailScenario.textContent = "-";
    elements.detailExploit.textContent = "-";
    elements.detailPoc.textContent = "-";
    elements.detailFix.textContent = "-";
    elements.detailSecureExample.textContent = "-";
    elements.detailOriginal.textContent = "-";
    elements.detailFixed.textContent = "-";
    elements.detailPatch.textContent = "-";
    elements.detailReference.textContent = "-";
    elements.detailReference.href = "#";
    return;
  }

  const title = item.vulnerability_title || item.vulnerability_type || "Finding";
  elements.detailTitle.textContent = title;
  elements.detailMeta.textContent =
    `${item.severity} | CVSS ${Number(item.cvss_score || 0).toFixed(1)} | ` +
    `${item.file_path}:${item.line_number} | ${item.cwe_id || "N/A"} | ${item.owasp_mapping || "N/A"}`;

  elements.detailImpact.textContent = item.business_impact || "-";
  elements.detailScenario.textContent = item.attack_scenario || "-";
  elements.detailExploit.textContent = item.exploitation_example || "-";
  elements.detailPoc.textContent = item.proof_of_concept || "-";
  elements.detailFix.textContent = item.recommendation || "-";
  elements.detailSecureExample.textContent = item.secure_code_example || "-";
  elements.detailOriginal.textContent = item.original_code || item.vulnerable_code_snippet || item.evidence || "-";
  elements.detailFixed.textContent = item.fixed_code || item.secure_code_example || item.recommendation || "-";
  elements.detailPatch.textContent = item.patch_preview || "-";

  if (item.reference) {
    elements.detailReference.textContent = item.reference;
    elements.detailReference.href = item.reference;
  } else {
    elements.detailReference.textContent = "-";
    elements.detailReference.href = "#";
  }
}

function renderFindingsTable() {
  const findings = getFilteredFindings();
  state.filteredFindings = findings;

  if (!findings.length) {
    elements.findingsTableBody.innerHTML = "<tr><td colspan='5'>No findings for the current filter/query.</td></tr>";
    renderFindingDetail(null);
    return;
  }

  if (!state.selectedFindingKey || !findings.some((item) => findingKey(item) === state.selectedFindingKey)) {
    state.selectedFindingKey = findingKey(findings[0]);
  }

  const rows = findings
    .map((item) => {
      const selected = findingKey(item) === state.selectedFindingKey;
      const severityClass = `sev-${String(item.severity).toLowerCase()}`;
      const title = item.vulnerability_title || item.vulnerability_type;
      const location = `${item.file_path}:${item.line_number}`;

      return `
        <tr class="finding-row ${selected ? "selected" : ""}" data-finding-key="${escapeHtml(findingKey(item))}">
          <td><span class="severity-pill ${severityClass}">${escapeHtml(item.severity)}</span></td>
          <td>${escapeHtml(title)}</td>
          <td>${Number(item.cvss_score || 0).toFixed(1)}</td>
          <td>${escapeHtml(item.cwe_id || "N/A")}</td>
          <td>${escapeHtml(location)}</td>
        </tr>
      `;
    })
    .join("");

  elements.findingsTableBody.innerHTML = rows;
  const selectedFinding = findings.find((item) => findingKey(item) === state.selectedFindingKey) || findings[0];
  renderFindingDetail(selectedFinding);
}

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text || "");
    setMessage("Copied to clipboard.");
  } catch (_) {
    setMessage("Unable to access clipboard in this browser context.", true);
  }
}

async function pollScan(scanId) {
  try {
    const status = await fetchStatus(scanId);
    updateProgress(status.progress_percent);

    const detail = status.current_file ? ` | ${status.current_file}` : "";
    elements.scanStatusMeta.textContent = `${status.status.toUpperCase()} - ${status.stage}${detail}`;
    setMessage(status.message || "Scanning in progress");

    if (status.status === "failed") {
      clearInterval(state.pollHandle);
      state.pollHandle = null;
      elements.scanButton.disabled = false;
      setMessage(status.message || "Scan failed", true);
      return;
    }

    if (status.status === "completed") {
      clearInterval(state.pollHandle);
      state.pollHandle = null;

      const report = await fetchResults(scanId);
      state.report = report;
      renderSummary(report);
      renderControls(report);
      renderFindingsTable();

      elements.reportSwitch.classList.remove("hidden");
      switchReportView("vulnerability");
      enableExportButtons(true);
      elements.scanButton.disabled = false;
      elements.scanStatusMeta.textContent = "COMPLETED";
      setMessage("Scan completed. Split reports and exports are ready.");
    }
  } catch (error) {
    clearInterval(state.pollHandle);
    state.pollHandle = null;
    elements.scanButton.disabled = false;
    setMessage(error.message || "Unexpected error while polling scan", true);
  }
}

elements.form.addEventListener("submit", async (event) => {
  event.preventDefault();

  const targetPath = elements.targetPath.value.trim();
  if (!targetPath) {
    setMessage("Please provide a target folder path.", true);
    return;
  }

  elements.scanButton.disabled = true;
  elements.reportSwitch.classList.add("hidden");
  elements.dashboardSection.classList.add("hidden");
  elements.controlsSection.classList.add("hidden");
  elements.findingsSection.classList.add("hidden");
  enableExportButtons(false);
  state.report = null;
  state.searchQuery = "";
  state.selectedFindingKey = null;
  state.currentSeverityFilter = "All";
  state.currentReportView = "vulnerability";
  elements.findingSearch.value = "";
  activateFilterButton("All");
  activateReportTab("vulnerability");
  updateProgress(0);
  elements.scanStatusMeta.textContent = "QUEUED";
  setMessage("Initializing enterprise scan pipeline...");

  try {
    const payload = await startScan(targetPath);
    state.scanId = payload.scan_id;

    if (state.pollHandle) {
      clearInterval(state.pollHandle);
    }
    state.pollHandle = setInterval(() => {
      pollScan(state.scanId);
    }, 1200);
    pollScan(state.scanId);
  } catch (error) {
    elements.scanButton.disabled = false;
    setMessage(error.message || "Unable to start scan", true);
    elements.scanStatusMeta.textContent = "FAILED";
  }
});

elements.filters.addEventListener("click", (event) => {
  const target = event.target;
  if (!(target instanceof HTMLButtonElement)) {
    return;
  }
  const severity = target.dataset.severity;
  if (!severity) {
    return;
  }

  state.currentSeverityFilter = severity;
  activateFilterButton(severity);
  renderFindingsTable();
});

elements.findingSearch.addEventListener("input", () => {
  state.searchQuery = elements.findingSearch.value || "";
  renderFindingsTable();
});

elements.findingsTableBody.addEventListener("click", (event) => {
  const target = event.target;
  if (!(target instanceof Element)) {
    return;
  }
  const row = target.closest("tr[data-finding-key]");
  if (!row) {
    return;
  }

  const key = row.getAttribute("data-finding-key");
  if (!key) {
    return;
  }

  state.selectedFindingKey = key;
  renderFindingsTable();
});

elements.exportButtons.forEach((button) => {
  button.addEventListener("click", () => {
    if (!state.scanId) {
      return;
    }
    const format = button.dataset.format;
    const reportType = button.dataset.reportType || "combined";
    if (!format) {
      return;
    }
    window.open(
      `/api/scans/${state.scanId}/export?fmt=${encodeURIComponent(format)}&report_type=${encodeURIComponent(reportType)}`,
      "_blank"
    );
  });
});

elements.railLinks.forEach((button) => {
  button.addEventListener("click", () => {
    if (!state.report) {
      return;
    }
    const targetId = button.dataset.target;
    if (!targetId) {
      return;
    }

    if (targetId === "controlsSection") {
      switchReportView("existing");
      elements.controlsSection.scrollIntoView({ behavior: "smooth", block: "start" });
      return;
    }

    if (targetId === "dashboardSection" || targetId === "findingsSection") {
      switchReportView("vulnerability");
      const section = document.getElementById(targetId);
      if (section && !section.classList.contains("hidden")) {
        section.scrollIntoView({ behavior: "smooth", block: "start" });
      }
    }
  });
});

elements.reportTabs.forEach((button) => {
  button.addEventListener("click", () => {
    const view = button.dataset.view;
    if (!view || !state.report) {
      return;
    }
    switchReportView(view);
  });
});

if (elements.copyFixedCodeBtn) {
  elements.copyFixedCodeBtn.addEventListener("click", () => copyText(elements.detailFixed.textContent || ""));
}

if (elements.copyPatchBtn) {
  elements.copyPatchBtn.addEventListener("click", () => copyText(elements.detailPatch.textContent || ""));
}
