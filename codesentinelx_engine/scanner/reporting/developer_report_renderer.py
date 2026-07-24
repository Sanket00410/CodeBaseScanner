from __future__ import annotations

import html as _html
from datetime import datetime, timezone
from typing import Any

from .report_models import (
    AttackChain,
    ComplianceFrameworkMapping,
    DataFlowStep,
    DeveloperReport,
    EvidenceItem,
    FindingGroup,
    ProfessionalFinding,
    ProfessionalReportMetadata,
    RemediationGuidance,
    ReportValidationWarning,
    RootCauseGrouping,
    SBOMEntry,
    SecurityMetricsDashboard,
    SecurityPostureScores,
    AssessmentLimitation,
)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _e(text: Any) -> str:
    return _html.escape(str(text))


def _css() -> str:
    return """<style>
:root {
  --critical: #dc2626; --high: #ea580c; --medium: #d97706; --low: #2563eb; --info: #6b7280;
  --critical-light: #fef2f2; --high-light: #fff7ed; --medium-light: #fffbeb; --low-light: #eff6ff; --info-light: #f9fafb;
  --bg: #ffffff; --bg-alt: #f9fafb; --text: #111827; --text-muted: #6b7280;
  --border: #e5e7eb; --accent: #1e40af; --accent-light: #dbeafe;
  --green: #16a34a; --green-light: #f0fdf4; --red: #dc2626; --red-light: #fef2f2;
}
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; color: var(--text); line-height: 1.6; background: var(--bg); font-size: 14px; }
.page { max-width: 960px; margin: 0 auto; padding: 40px 48px; }
.cover { display: flex; flex-direction: column; justify-content: center; align-items: center; min-height: 100vh; background: linear-gradient(135deg, #0f172a, #1e3a5f); color: white; text-align: center; page-break-after: always; }
.cover h1 { font-size: 2.6rem; margin-bottom: 8px; font-weight: 700; }
.cover .subtitle { font-size: 1.1rem; opacity: 0.85; margin-bottom: 32px; }
.cover-badge { background: #dc2626; padding: 4px 16px; border-radius: 4px; font-size: 0.75rem; font-weight: 700; letter-spacing: 0.1em; margin-bottom: 20px; }
.cover-meta-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; width: 100%; max-width: 700px; margin: 24px 0; }
.cover-meta-item { background: rgba(255,255,255,0.1); border-radius: 8px; padding: 12px; text-align: left; }
.cover-meta-label { font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.05em; opacity: 0.7; }
.cover-meta-value { font-size: 0.95rem; font-weight: 600; }
.cover-posture { margin-top: 32px; }
.cover-posture-label { font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em; opacity: 0.7; margin-bottom: 4px; }
.cover-posture-score { font-size: 3rem; font-weight: 800; }
.cover-posture-max { font-size: 1.2rem; opacity: 0.5; }
.meta-footer { font-size: 0.8rem; opacity: 0.5; margin-top: 32px; }
h2 { font-size: 1.4rem; color: var(--accent); border-bottom: 2px solid var(--accent); padding-bottom: 8px; margin: 32px 0 16px; }
h3 { font-size: 1.15rem; margin: 20px 0 10px; }
h4 { font-size: 1rem; margin: 12px 0 6px; color: var(--text-muted); }
.severity-badge { display: inline-block; padding: 2px 10px; border-radius: 12px; font-size: 0.8rem; font-weight: 600; color: white; }
.severity-badge.critical { background: var(--critical); }
.severity-badge.high { background: var(--high); }
.severity-badge.medium { background: var(--medium); }
.severity-badge.low { background: var(--low); }
.severity-badge.info { background: var(--info); }
table { width: 100%; border-collapse: collapse; margin: 16px 0; font-size: 0.9rem; }
th { background: var(--bg-alt); text-align: left; padding: 10px 12px; border-bottom: 2px solid var(--border); font-weight: 600; }
td { padding: 10px 12px; border-bottom: 1px solid var(--border); }
tr:hover { background: var(--bg-alt); }
.mini-table { width: auto; min-width: 300px; }
.mini-table td { padding: 6px 12px; }
.finding-card { border: 1px solid var(--border); border-radius: 8px; padding: 24px; margin: 20px 0; page-break-inside: avoid; }
.finding-card .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }
.finding-card h3 { margin: 0; color: var(--text); }
.evidence-block { background: #1e293b; color: #e2e8f0; border-left: 3px solid var(--accent); padding: 12px 16px; margin: 12px 0; font-family: 'JetBrains Mono', 'Fira Code', monospace; font-size: 0.82rem; white-space: pre-wrap; overflow-x: auto; border-radius: 0 6px 6px 0; }
.code-fix { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin: 12px 0; }
.code-fix .vulnerable, .code-fix .fixed { border-radius: 6px; overflow: hidden; }
.code-fix .label { padding: 6px 12px; font-size: 0.75rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; }
.code-fix .vulnerable .label { background: #fef2f2; color: var(--critical); }
.code-fix .fixed .label { background: #f0fdf4; color: var(--green); }
.code-fix pre { margin: 0; padding: 12px; background: #1e293b; color: #e2e8f0; font-size: 0.82rem; overflow-x: auto; }
.attack-chain { border: 2px solid var(--critical); border-radius: 8px; padding: 24px; margin: 20px 0; }
.chain-step { display: flex; gap: 16px; padding: 12px 0; border-bottom: 1px dashed var(--border); }
.chain-step:last-child { border-bottom: none; }
.step-number { width: 36px; height: 36px; border-radius: 50%; background: var(--critical); color: white; display: flex; align-items: center; justify-content: center; font-weight: 700; flex-shrink: 0; }
.remediation-item { padding: 16px; border-left: 4px solid var(--accent); margin: 12px 0; background: var(--bg-alt); border-radius: 0 6px 6px 0; }
.toc a { text-decoration: none; color: var(--accent); display: block; padding: 4px 0; }
.toc a:hover { text-decoration: underline; }
.dashboard-grid { display: grid; grid-template-columns: repeat(5, 1fr); gap: 12px; margin: 16px 0; }
.dashboard-card { text-align: center; padding: 16px; border-radius: 8px; }
.dashboard-card .count { font-size: 2rem; font-weight: 700; }
.dashboard-card .label { font-size: 0.8rem; opacity: 0.8; }
.metrics-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin: 16px 0; }
.metric-card { text-align: center; padding: 16px; border-radius: 8px; background: var(--bg-alt); border: 1px solid var(--border); }
.metric-value { font-size: 1.8rem; font-weight: 700; }
.metric-label { font-size: 0.85rem; font-weight: 600; margin-top: 4px; }
.metric-desc { font-size: 0.72rem; color: var(--text-muted); margin-top: 2px; }
.methodology { background: var(--bg-alt); padding: 20px; border-radius: 8px; margin: 16px 0; }
.methodology p { margin: 4px 0; }
.footer { text-align: center; padding: 32px; color: var(--text-muted); font-size: 0.8rem; border-top: 1px solid var(--border); margin-top: 40px; }
.exec-grid { display: grid; grid-template-columns: 1fr 280px; gap: 24px; }
.exec-main { }
.exec-sidebar { }
.exec-text { font-size: 0.95rem; line-height: 1.7; margin-bottom: 16px; }
.exec-box { padding: 16px; border-left: 4px solid var(--critical); background: var(--bg-alt); border-radius: 0 6px 6px 0; margin: 12px 0; }
.exec-section { margin: 16px 0; }
.exec-list { padding-left: 20px; }
.exec-list li { margin: 4px 0; font-size: 0.9rem; }
.posture-scores { background: var(--bg-alt); border: 1px solid var(--border); border-radius: 8px; padding: 16px; }
.posture-item { display: flex; align-items: center; gap: 8px; margin: 8px 0; }
.posture-label { font-size: 0.78rem; width: 100px; flex-shrink: 0; }
.posture-bar { flex: 1; height: 8px; background: var(--border); border-radius: 4px; overflow: hidden; }
.posture-fill { height: 100%; border-radius: 4px; transition: width 0.3s; }
.posture-val { font-size: 0.8rem; font-weight: 600; width: 30px; text-align: right; }
.gap-analysis { margin-top: 12px; padding-top: 12px; border-top: 1px solid var(--border); }
.small-text { font-size: 0.82rem; color: var(--text-muted); }
.status-pass { color: var(--green); font-weight: 600; }
.status-fail { color: var(--red); font-weight: 600; }
.severity-summary { margin: 12px 0; padding: 12px; background: var(--bg-alt); border-radius: 6px; }
.data-flow { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; margin: 12px 0; padding: 12px; background: var(--bg-alt); border-radius: 6px; }
.data-flow-step { padding: 6px 12px; border-radius: 4px; font-size: 0.82rem; font-weight: 600; }
.data-flow-arrow { color: var(--text-muted); font-weight: 700; }
.data-flow-source { background: #fee2e2; color: #991b1b; }
.data-flow-validation { background: #fef3c7; color: #92400e; }
.data-flow-processing { background: #dbeafe; color: #1e40af; }
.data-flow-sink { background: #fce7f3; color: #9d174d; }
.confidence-tag { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: 600; }
.confidence-tp { background: #dcfce7; color: #166534; }
.confidence-lp { background: #fef9c3; color: #854d0e; }
.confidence-nmr { background: #e0e7ff; color: #3730a3; }
.confidence-pfp { background: #fee2e2; color: #991b1b; }
.compliance-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin: 16px 0; }
.compliance-card { padding: 16px; border: 1px solid var(--border); border-radius: 8px; }
.compliance-card h4 { margin-top: 0; }
.compliance-bar { height: 8px; background: var(--border); border-radius: 4px; margin: 8px 0; overflow: hidden; }
.compliance-fill { height: 100%; border-radius: 4px; }
.phase-section { margin: 16px 0; border: 1px solid var(--border); border-radius: 8px; overflow: hidden; }
.phase-header { padding: 12px 16px; font-weight: 700; font-size: 0.95rem; }
.phase-header.phase1 { background: #fef2f2; color: #991b1b; border-bottom: 2px solid #dc2626; }
.phase-header.phase2 { background: #fff7ed; color: #9a3412; border-bottom: 2px solid #ea580c; }
.phase-header.phase3 { background: #fffbeb; color: #92400e; border-bottom: 2px solid #d97706; }
.phase-header.phase4 { background: #eff6ff; color: #1e40af; border-bottom: 2px solid #2563eb; }
.phase-body { padding: 12px 16px; }
.posture-full { display: grid; grid-template-columns: repeat(2, 1fr); gap: 16px; margin: 16px 0; }
.posture-full-card { padding: 16px; border: 1px solid var(--border); border-radius: 8px; text-align: center; }
.posture-full-score { font-size: 2.5rem; font-weight: 800; }
.posture-full-label { font-size: 0.85rem; color: var(--text-muted); }
.limitation-item { padding: 12px 16px; border-left: 4px solid var(--medium); margin: 12px 0; background: var(--bg-alt); border-radius: 0 6px 6px 0; }
.validation-note { padding: 8px 12px; background: #fef3c7; border-radius: 4px; margin: 4px 0; font-size: 0.85rem; }
.kb-list { padding-left: 20px; }
.kb-list li { margin: 4px 0; font-size: 0.9rem; }
.root-cause-card { padding: 16px; border: 1px solid var(--border); border-radius: 8px; margin: 12px 0; }
.root-cause-card h4 { margin-top: 0; }
.validation-banner { padding: 12px 16px; margin: 16px 0; border-radius: 8px; font-size: 0.9rem; }
.validation-banner.warning { background: #fef3c7; border: 1px solid #f59e0b; color: #92400e; }
.validation-banner.error { background: #fef2f2; border: 1px solid #dc2626; color: #991b1b; }
.validation-banner.info { background: #eff6ff; border: 1px solid #2563eb; color: #1e40af; }
.validation-banner strong { display: block; margin-bottom: 4px; }
.finding-group-card { padding: 16px; border: 2px solid var(--accent); border-radius: 8px; margin: 12px 0; background: var(--accent-light); }
.finding-group-card h4 { margin-top: 0; color: var(--accent); }
.group-file-list { font-size: 0.82rem; color: var(--text-muted); }
.evidence-quality { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: 600; }
.eq-high { background: #dcfce7; color: #166534; }
.eq-medium { background: #fef9c3; color: #854d0e; }
.eq-low { background: #fee2e2; color: #991b1b; }
.func-tag { display: inline-block; padding: 1px 6px; border-radius: 3px; font-size: 0.75rem; font-family: monospace; background: var(--bg-alt); border: 1px solid var(--border); margin: 2px; }
.var-tag { display: inline-block; padding: 1px 6px; border-radius: 3px; font-size: 0.75rem; font-family: monospace; background: #e0e7ff; color: #3730a3; margin: 2px; }
@media print {
  .page { padding: 20px; }
  .cover { min-height: auto; padding: 60px 40px; }
  .finding-card { page-break-inside: avoid; }
  .code-fix { grid-template-columns: 1fr; }
}
</style>"""


class DeveloperReportRenderer:
    def render_html(self, report: DeveloperReport) -> str:
        sections = []
        if report.validation_warnings:
            sections.append(self._render_validation_banner(report))
        sections.extend([
            self._render_cover_page(report),
            self._render_table_of_contents(report),
            self._render_executive_summary(report),
            self._render_security_metrics_dashboard(report),
            self._render_severity_dashboard(report),
            self._render_methodology(report),
            self._render_findings_overview(report),
        ])
        for idx, finding in enumerate(report.findings, 1):
            sections.append(self._render_finding_detail(finding, idx))
        if report.grouped_findings:
            sections.append(self._render_finding_groups(report))
        if report.attack_chains:
            sections.append(self._render_attack_chains(report))
        sections.append(self._render_root_cause_analysis(report))
        sections.append(self._render_sbom_summary(report))
        sections.append(self._render_compliance_mapping(report))
        sections.append(self._render_phased_remediation_roadmap(report))
        sections.append(self._render_developer_fix_guidance(report))
        sections.append(self._render_assessment_limitations(report))
        sections.append(self._render_security_posture_section(report))
        sections.append(self._render_appendix(report))
        return self._wrap_html("\n".join(sections))

    def _wrap_html(self, body: str) -> str:
        return (
            '<!DOCTYPE html>\n<html lang="en">\n<head>\n<meta charset="UTF-8">\n'
            '<meta name="viewport" content="width=device-width, initial-scale=1.0">\n'
            '<title>CodeSentinelX Enterprise Security Assessment Report</title>\n'
            + _css()
            + '\n</head>\n<body>\n'
            + body
            + '\n</body>\n</html>'
        )

    def _render_cover_page(self, report: DeveloperReport) -> str:
        meta = report.metadata
        scan = meta.scan_metadata
        scores = meta.security_posture_scores
        posture_color = "#dc2626" if scores.overall_score < 40 else "#ea580c" if scores.overall_score < 70 else "#16a34a"
        return (
            '<div class="cover page">'
            '<div class="cover-badge">CONFIDENTIAL</div>'
            '<h1>Enterprise Security<br>Assessment Report</h1>'
            '<p class="subtitle">CodeSentinelX Professional Analysis</p>'
            '<div class="cover-meta-grid">'
            '<div class="cover-meta-item"><div class="cover-meta-label">Project</div>'
            f'<div class="cover-meta-value">{_e(meta.report_title or "CodeSentinelX Security Scan")}</div></div>'
            '<div class="cover-meta-item"><div class="cover-meta-label">Target</div>'
            f'<div class="cover-meta-value">{_e(scan.target_path or "N/A")}</div></div>'
            '<div class="cover-meta-item"><div class="cover-meta-label">Scanner</div>'
            f'<div class="cover-meta-value">{_e(scan.scanner_name)} v{_e(scan.scanner_version)}</div></div>'
            '<div class="cover-meta-item"><div class="cover-meta-label">Generated</div>'
            f'<div class="cover-meta-value">{_e(meta.generated_at or _now_iso())}</div></div>'
            '<div class="cover-meta-item"><div class="cover-meta-label">Files Scanned</div>'
            f'<div class="cover-meta-value">{scan.files_scanned}</div></div>'
            '<div class="cover-meta-item"><div class="cover-meta-label">Total Findings</div>'
            f'<div class="cover-meta-value">{meta.total_findings}</div></div>'
            '</div>'
            '<div class="cover-posture">'
            '<div class="cover-posture-label">Security Posture Score</div>'
            f'<div class="cover-posture-score" style="color: {posture_color};">{scores.overall_score:.0f}'
            '<span class="cover-posture-max">/100</span></div></div>'
            f'<p class="meta-footer">Generated by {_e(scan.scanner_name)} v{_e(scan.scanner_version)} | '
            f'{_e(meta.classification)} | Automated scan with manual review recommended</p>'
            '</div>'
        )

    def _render_table_of_contents(self, report: DeveloperReport) -> str:
        items = [
            "<a href='#exec-summary'>1. Executive Summary</a>",
            "<a href='#security-metrics'>2. Security Metrics Dashboard</a>",
            "<a href='#severity-dashboard'>3. Severity Distribution</a>",
            "<a href='#methodology'>4. Methodology</a>",
            "<a href='#findings-overview'>5. Findings Overview</a>",
        ]
        for i, f in enumerate(report.findings, 1):
            items.append(f"<a href='#finding-{i}'>5.{i} F-{i:03d}: {_e(f.title)}</a>")
        toc_offset = 6
        if report.grouped_findings:
            items.append(f"<a href='#finding-groups'>{toc_offset}. Finding Groups</a>")
            toc_offset += 1
        for label, anchor in [
            ("Attack Chains", "attack-chains"),
            ("Root Cause Analysis", "root-cause"),
            ("SBOM Summary", "sbom"),
            ("Compliance Mapping", "compliance"),
            ("Remediation Roadmap", "remediation-roadmap"),
            ("Developer Fix Guidance", "fix-guidance"),
            ("Assessment Limitations", "limitations"),
            ("Security Posture", "posture"),
            ("Appendix", "appendix"),
        ]:
            if toc_offset <= 15:
                items.append(f"<a href='#{anchor}'>{toc_offset}. {label}</a>")
                toc_offset += 1
        return (
            '<div class="page"><h2>Table of Contents</h2>'
            '<div class="toc">' + "".join(items) + '</div></div>'
        )

    def _render_executive_summary(self, report: DeveloperReport) -> str:
        meta = report.metadata
        scores = meta.security_posture_scores
        stats = meta.scan_statistics
        scan = meta.scan_metadata
        risk_color = "#dc2626" if meta.risk_rating in ("Critical", "High") else "#d97706" if meta.risk_rating == "Medium" else "#2563eb"
        sections = [
            '<div class="page" id="exec-summary">',
            '<h2>1. Executive Summary</h2>',
            '<div class="exec-grid"><div class="exec-main">',
            f'<p class="exec-text">{_e(meta.executive_summary_text or report.executive_summary)}</p>',
            f'<div class="exec-box" style="border-left-color: {risk_color};">',
            f'<strong>Overall Risk Rating: <span class="severity-badge {meta.risk_rating.lower()}">{_e(meta.risk_rating.upper())}</span></strong>',
            f'<br>Total findings: {meta.total_findings} | Attack chains: {len(report.attack_chains)}',
            f'<br>Risk Score: {meta.risk_score:.1f}/10</div>',
        ]
        if meta.critical_risk_drivers:
            items = "".join(f"<li>{_e(d)}</li>" for d in meta.critical_risk_drivers)
            sections.append(f'<div class="exec-section"><h3>Critical Risk Drivers</h3><ul class="exec-list">{items}</ul></div>')
        if meta.top_5_security_risks:
            items = "".join(f"<li>{_e(r)}</li>" for r in meta.top_5_security_risks)
            sections.append(f'<div class="exec-section"><h3>Top Security Risks</h3><ol class="exec-list">{items}</ol></div>')
        if meta.business_impact_assessment:
            sections.append(f'<div class="exec-section"><h3>Business Impact Assessment</h3><p>{_e(meta.business_impact_assessment)}</p></div>')
        if stats:
            lang_bd = stats.get("language_breakdown", {})
            lang_text = ", ".join(f"{k}: {v}" for k, v in lang_bd.items()) if lang_bd else "N/A"
            sections.append(
                '<div class="exec-section"><h3>Scan Coverage Statistics</h3><table class="mini-table">'
                f'<tr><td>Files Scanned</td><td>{stats.get("files_scanned", scan.files_scanned)}</td></tr>'
                f'<tr><td>Lines of Code</td><td>{stats.get("total_lines_of_code", "N/A")}</td></tr>'
                f'<tr><td>Languages</td><td>{_e(lang_text)}</td></tr>'
                f'<tr><td>Scan Duration</td><td>{stats.get("scan_duration_seconds", scan.duration_seconds):.1f}s</td></tr>'
                f'<tr><td>Coverage</td><td>{stats.get("scan_coverage_percent", 0):.1f}%</td></tr></table></div>'
            )
        sections.append('</div><div class="exec-sidebar">')
        sections.append(self._render_posture_scores_sidebar(scores))
        sections.append('</div></div></div>')
        return "\n".join(sections)

    def _render_posture_scores_sidebar(self, scores: SecurityPostureScores) -> str:
        def bar(score: float, label: str) -> str:
            color = "#dc2626" if score < 40 else "#ea580c" if score < 70 else "#16a34a"
            return (
                f'<div class="posture-item"><div class="posture-label">{label}</div>'
                f'<div class="posture-bar"><div class="posture-fill" style="width:{score:.0f}%;background:{color};"></div></div>'
                f'<div class="posture-val" style="color:{color};">{score:.0f}</div></div>'
            )
        parts = ['<div class="posture-scores"><h3>Security Posture</h3>']
        for label, val in [
            ("Overall", scores.overall_score),
            ("App Security", scores.application_security_score),
            ("Supply Chain", scores.supply_chain_score),
            ("Secrets", scores.secrets_management_score),
            ("Dependencies", scores.dependency_hygiene_score),
            ("Logging", scores.logging_maturity_score),
        ]:
            parts.append(bar(val, label))
        if scores.gap_analysis:
            parts.append(f'<div class="gap-analysis"><h4>Gap Analysis</h4><p class="small-text">{_e(scores.gap_analysis)}</p></div>')
        parts.append('</div>')
        return "\n".join(parts)

    def _render_security_metrics_dashboard(self, report: DeveloperReport) -> str:
        m = report.metadata.security_metrics
        cards_data = [
            ("Risk Score", f"{m.risk_score:.1f}", "Overall risk assessment", "#dc2626"),
            ("MTTR (hrs)", f"{m.mean_time_to_remediate_hours:.1f}", "Mean time to remediate", "#1e40af"),
            ("High-Risk Density", f"{m.high_risk_density:.2f}", "High-risk per 1K LOC", "#1e40af"),
            ("Security Debt", f"{m.security_debt_score:.1f}", "Security debt score", "#1e40af"),
            ("Compliance", f"{m.compliance_readiness:.0f}%", "Compliance readiness", "#16a34a"),
            ("Findings/1K LOC", f"{m.findings_per_1000_loc:.2f}", "Finding density", "#1e40af"),
            ("Scan Coverage", f"{m.scan_coverage_percent:.1f}%", "Code scan coverage", "#16a34a"),
        ]
        cards_html = ""
        for label, value, desc, color in cards_data:
            cards_html += (
                f'<div class="metric-card"><div class="metric-value" style="color:{color};">{_e(value)}</div>'
                f'<div class="metric-label">{_e(label)}</div><div class="metric-desc">{_e(desc)}</div></div>'
            )
        owasp_html = ""
        if m.owasp_coverage_matrix:
            rows = ""
            for cat, status in sorted(m.owasp_coverage_matrix.items()):
                cls = "pass" if status == "Pass" else "fail" if status == "Fail" else "info"
                rows += f'<tr><td>{_e(cat)}</td><td class="status-{cls}">{_e(status)}</td></tr>'
            owasp_html = (
                '<div class="owasp-matrix"><h3>OWASP Top 10 Coverage Matrix</h3>'
                '<table class="mini-table"><thead><tr><th>OWASP Category</th><th>Status</th></tr></thead>'
                f'<tbody>{rows}</tbody></table></div>'
            )
        return f'<div class="page" id="security-metrics"><h2>2. Security Metrics Dashboard</h2><div class="metrics-grid">{cards_html}</div>{owasp_html}</div>'

    def _render_severity_dashboard(self, report: DeveloperReport) -> str:
        counts = self._severity_counts(report)
        cards = []
        for sev in ["Critical", "High", "Medium", "Low", "Info"]:
            count = counts.get(sev, 0)
            cards.append(
                f'<div class="dashboard-card" style="background:var(--{sev.lower()}-light,var(--bg-alt));border:1px solid var(--{sev.lower()});">'
                f'<div class="count" style="color:var(--{sev.lower()});">{count}</div>'
                f'<div class="label">{sev}</div></div>'
            )
        total = len(report.findings)
        crit_high = counts.get("Critical", 0) + counts.get("High", 0)
        density = report.metadata.security_metrics.findings_per_1000_loc
        return (
            f'<div class="page" id="severity-dashboard"><h2>3. Severity Distribution</h2>'
            f'<div class="dashboard-grid">{"".join(cards)}</div>'
            f'<div class="severity-summary"><p><strong>Total:</strong> {total} findings | '
            f'<strong>Critical+High:</strong> {crit_high} | '
            f'<strong>Density:</strong> {density:.2f} per 1K LOC</p></div></div>'
        )

    def _render_methodology(self, report: DeveloperReport) -> str:
        scan = report.metadata.scan_metadata
        parts = [
            '<div class="page" id="methodology"><h2>4. Methodology</h2><div class="methodology">',
            f'<p><strong>Scanner:</strong> {_e(scan.scanner_name)} v{_e(scan.scanner_version)}</p>',
            '<p><strong>Analysis Type:</strong> Automated static analysis with dataflow tracking, control-flow analysis, and heuristic pattern matching.</p>',
            '<p><strong>Validation:</strong> Findings validated via deterministic source validation and parser-based flow analysis.</p>',
            '<p><strong>Standards:</strong> OWASP Testing Guide v4.2, CWE/SANS Top 25, NIST SP 800-53</p>',
            f'<p><strong>Environment:</strong> {_e(scan.scan_environment)}</p>',
            f'<p><strong>Duration:</strong> {scan.duration_seconds:.1f}s | Files scanned: {scan.files_scanned}</p>',
        ]
        if report.known_assumptions:
            items = "".join(f"<li>{_e(a)}</li>" for a in report.known_assumptions)
            parts.append(f'<p><strong>Known Assumptions:</strong></p><ul>{items}</ul>')
        if report.assessment_limitations:
            items = "".join(f'<li><strong>{_e(l.category)}:</strong> {_e(l.description)}</li>' for l in report.assessment_limitations[:3])
            parts.append(f'<p><strong>Key Limitations:</strong></p><ul>{items}</ul>')
        parts.append('</div></div>')
        return "\n".join(parts)

    def _render_findings_overview(self, report: DeveloperReport) -> str:
        rows = []
        for i, f in enumerate(report.findings, 1):
            sev_class = f.severity.lower()
            conf = f.confidence_level.value if hasattr(f.confidence_level, "value") else str(f.confidence_level)
            eq_score = f.confidence_score
            eq_cls = "eq-high" if eq_score >= 60 else "eq-medium" if eq_score >= 30 else "eq-low"
            rows.append(
                f'<tr><td>F-{i:03d}</td>'
                f'<td><span class="severity-badge {sev_class}">{_e(f.severity)}</span></td>'
                f'<td>{_e(f.title)}</td>'
                f'<td>{_e(f.file_path)}:{f.line_number}</td>'
                f'<td>{f.cvss_score:.1f}</td>'
                f'<td><code>{_e(f.cvss_vector_string[:35] if f.cvss_vector_string else "N/A")}</code></td>'
                f'<td>{_e(conf)}</td>'
                f'<td><span class="evidence-quality {eq_cls}">{eq_score:.0f}</span></td>'
                f'<td>{_e(f.root_cause_category or "N/A")}</td></tr>'
            )
        return (
            '<div class="page" id="findings-overview"><h2>5. Findings Overview</h2>'
            '<table><thead><tr><th>ID</th><th>Severity</th><th>Type</th><th>Location</th>'
            '<th>CVSS</th><th>Vector</th><th>Confidence</th><th>Evidence</th><th>Root Cause</th></tr></thead>'
            f'<tbody>{"".join(rows)}</tbody></table></div>'
        )

    # ── Rule 1: Validation warnings banner ────────────────────────────────────
    def _render_validation_banner(self, report: DeveloperReport) -> str:
        items = []
        for w in report.validation_warnings:
            css_cls = w.severity.lower() if w.severity.lower() in ("error", "warning", "info") else "warning"
            items.append(
                f'<div class="validation-banner {css_cls}">'
                f'<strong>[{_e(w.rule_id)}] {_e(w.severity)}: {_e(w.field_affected)}</strong>'
                f'{_e(w.message)}</div>'
            )
        return f'<div class="page">{" ".join(items)}</div>'

    # ── Rule 7: Finding groups rendering ──────────────────────────────────────
    def _render_finding_groups(self, report: DeveloperReport) -> str:
        if not report.grouped_findings:
            return ""
        cards = []
        for g in report.grouped_findings:
            if isinstance(g, FindingGroup):
                file_list = ", ".join(_e(f) for f in g.affected_files[:5])
                cards.append(
                    f'<div class="finding-group-card">'
                    f'<h4>{_e(g.group_id)}: {_e(g.group_type)}</h4>'
                    f'<p>{_e(g.description)}</p>'
                    f'<p class="group-file-list"><strong>Affected Files ({g.finding_count} findings):</strong> {file_list}</p>'
                    f'<p><strong>Remediation:</strong> {_e(g.remediation_summary)}</p>'
                    f'<p><strong>Representative Finding:</strong> {_e(g.representative_finding_uid)}</p>'
                    f'</div>'
                )
            elif isinstance(g, dict):
                cards.append(
                    f'<div class="finding-group-card">'
                    f'<h4>{_e(g.get("group_id", ""))}: {_e(g.get("group_type", ""))}</h4>'
                    f'<p>{_e(g.get("description", ""))}</p>'
                    f'</div>'
                )
        return f'<div class="page" id="finding-groups"><h2>6. Finding Groups (Deduplicated)</h2>{"".join(cards)}</div>'

    def _render_finding_detail(self, finding: ProfessionalFinding, index: int) -> str:
        sev_class = finding.severity.lower()
        uid = f"F-{index:03d}"
        eq_score = finding.confidence_score
        eq_cls = "eq-high" if eq_score >= 60 else "eq-medium" if eq_score >= 30 else "eq-low"
        parts = [
            f'<div class="finding-card" id="finding-{index}">',
            f'<div class="header"><h3>{uid}: {_e(finding.title)}</h3>',
            f'<span class="severity-badge {sev_class}">{_e(finding.severity)}</span></div>',
            '<table>',
            f'<tr><td><strong>Finding ID</strong></td><td>{_e(finding.vulnerability_id)}</td></tr>',
            f'<tr><td><strong>Location</strong></td><td>{_e(finding.file_path)}:{finding.line_number}</td></tr>',
            f'<tr><td><strong>CVSS Base</strong></td><td>{finding.cvss_score:.1f} | <code>{_e(finding.cvss_vector_string)}</code></td></tr>',
        ]
        if finding.cvss_temporal_score:
            parts.append(f'<tr><td><strong>CVSS Temporal</strong></td><td>{finding.cvss_temporal_score:.1f}</td></tr>')
        if finding.cvss_environmental_score:
            parts.append(f'<tr><td><strong>CVSS Environmental</strong></td><td>{finding.cvss_environmental_score:.1f}</td></tr>')
        if finding.cvss_scoring_rationale:
            parts.append(f'<tr><td><strong>Scoring Rationale</strong></td><td>{_e(finding.cvss_scoring_rationale)}</td></tr>')
        conf_level = finding.confidence_level.value if hasattr(finding.confidence_level, "value") else str(finding.confidence_level)
        conf_cls = {
            "True Positive": "tp", "Likely Positive": "lp",
            "Needs Manual Review": "nmr", "Potential False Positive": "pfp",
        }.get(conf_level, "nmr")
        parts.append(f'<tr><td><strong>Confidence</strong></td><td><span class="confidence-tag confidence-{conf_cls}">{_e(conf_level)}</span></td></tr>')
        if finding.confidence_explanation:
            parts.append(f'<tr><td><strong>Confidence Explanation</strong></td><td>{_e(finding.confidence_explanation)}</td></tr>')
        parts.append(f'<tr><td><strong>Evidence Quality</strong></td><td><span class="evidence-quality {eq_cls}">{eq_score:.0f}/100</span></td></tr>')
        if finding.rule_id:
            parts.append(f'<tr><td><strong>Rule ID</strong></td><td>{_e(finding.rule_id)}</td></tr>')
        if finding.cwe_id:
            parts.append(f'<tr><td><strong>CWE</strong></td><td>{_e(finding.cwe_id)}</td></tr>')
        parts.append('</table>')
        if finding.affected_functions:
            tags = "".join(f'<span class="func-tag">{_e(f)}</span>' for f in finding.affected_functions)
            parts.append(f'<h3>Affected Functions</h3><div>{tags}</div>')
        if finding.affected_parameters:
            tags = "".join(f'<span class="var-tag">{_e(v)}</span>' for v in finding.affected_parameters)
            parts.append(f'<h3>Affected Variables</h3><div>{tags}</div>')
        if finding.description:
            parts.append(f'<h3>Description</h3><p>{_e(finding.description)}</p>')
        if finding.technical_explanation:
            parts.append(f'<h3>Technical Analysis</h3><p>{_e(finding.technical_explanation)}</p>')
        if finding.attack_vector:
            parts.append(f'<h3>Attack Vector</h3><p>{_e(finding.attack_vector)}</p>')
        if finding.attack_preconditions:
            items = "".join(f"<li>{_e(p)}</li>" for p in finding.attack_preconditions)
            parts.append(f'<h3>Attack Preconditions</h3><ul>{items}</ul>')
        if finding.likelihood:
            parts.append(f'<h3>Likelihood</h3><p>{_e(finding.likelihood)}</p>')
        if finding.business_impact:
            parts.append(f'<h3>Business Impact</h3><p>{_e(finding.business_impact)}</p>')
        if finding.technical_impact:
            parts.append(f'<h3>Technical Impact</h3><p>{_e(finding.technical_impact)}</p>')
        if finding.risk_justification:
            parts.append(f'<h3>Risk Justification</h3><p>{_e(finding.risk_justification)}</p>')
        if finding.data_flow_steps:
            parts.append(self._render_data_flow(finding))
        parts.extend(self._render_evidence_section(finding))
        if finding.remediation:
            parts.append(self._render_remediation_section(finding.remediation))
        if finding.compliance_mapping:
            parts.append(self._render_finding_compliance(finding))
        if finding.references:
            parts.append(self._render_references_section(finding.references))
        parts.append('</div>')
        return "\n".join(parts)

    def _render_data_flow(self, finding: ProfessionalFinding) -> str:
        steps = []
        for dfs in finding.data_flow_steps:
            step_type = dfs.step_type.lower() if hasattr(dfs, "step_type") else "processing"
            css_class = {
                "source": "data-flow-source", "validation": "data-flow-validation",
                "processing": "data-flow-processing", "sink": "data-flow-sink",
                "transformation": "data-flow-processing",
            }.get(step_type, "data-flow-processing")
            label = dfs.step_type if hasattr(dfs, "step_type") else "Processing"
            desc = dfs.description if hasattr(dfs, "description") else ""
            steps.append(f'<span class="data-flow-step {css_class}">{_e(label)}: {_e(desc)}</span>')
        arrow = '<span class="data-flow-arrow">&rarr;</span>'
        return f'<h3>Data Flow Analysis</h3><div class="data-flow">{arrow.join(steps)}</div>'

    def _render_evidence_section(self, finding: ProfessionalFinding) -> list[str]:
        blocks = []
        for ev in finding.evidence:
            content = ev.data.get("content", "")
            if ev.evidence_type == "code_snippet":
                lang = ev.data.get("language", "")
                blocks.append(
                    f'<h4>Source Evidence</h4>'
                    f'<div class="evidence-block" data-language="{_e(lang)}">{_e(content)}</div>'
                )
            elif ev.evidence_type == "poc_narrative":
                blocks.append(f'<h4>Proof of Concept</h4><div class="evidence-block">{_e(content)}</div>')
            elif ev.evidence_type == "validation_result":
                status = ev.data.get("validation_status", "unknown")
                blocks.append(
                    f'<h4>Validation Result</h4>'
                    f'<p>Status: <strong>{_e(str(status))}</strong></p>'
                    f'<div class="evidence-block">{_e(content)}</div>'
                )
            elif ev.evidence_type == "http_exchange":
                req = ev.http_request
                resp = ev.http_response
                if req:
                    http_lines = [f"{req.method} {req.url}"]
                    for k, v in req.headers.items():
                        http_lines.append(f"{k}: {v}")
                    if req.body:
                        http_lines.extend(["", req.body])
                    if resp:
                        http_lines.extend(["", f"HTTP/1.1 {resp.status_code} {resp.status_text}"])
                        for k, v in resp.headers.items():
                            http_lines.append(f"{k}: {v}")
                    blocks.append(
                        f'<h4>HTTP Evidence</h4>'
                        f'<div class="evidence-block">{_e(chr(10).join(http_lines))}</div>'
                    )
        if not blocks and not finding.code_snippet_vulnerable:
            blocks.append('<h4>Evidence</h4><p class="small-text">Manual validation required. No automated evidence captured.</p>')
        return ["<h3>Evidence</h3>"] + blocks if blocks else []

    def _render_remediation_section(self, remediation: RemediationGuidance) -> str:
        parts = ["<h3>Remediation</h3>"]
        if remediation.title:
            parts.append(f'<h4>{_e(remediation.title)}</h4>')
        if remediation.description:
            parts.append(f'<p>{_e(remediation.description)}</p>')
        if remediation.complexity:
            parts.append(f'<p><strong>Complexity:</strong> {_e(remediation.complexity)} | <strong>Effort:</strong> {remediation.effort_hours:.1f} hours</p>')
        if remediation.code_example and remediation.fixed_code_example:
            parts.append(
                '<div class="code-fix">'
                '<div class="vulnerable"><div class="label">Vulnerable Code</div>'
                f'<pre>{_e(remediation.code_example)}</pre></div>'
                '<div class="fixed"><div class="label">Fixed Code</div>'
                f'<pre>{_e(remediation.fixed_code_example)}</pre></div></div>'
            )
        elif remediation.code_example:
            parts.append(
                '<div class="code-fix"><div class="vulnerable"><div class="label">Vulnerable Code</div>'
                f'<pre>{_e(remediation.code_example)}</pre></div></div>'
            )
        if remediation.references:
            ref_list = ", ".join(_e(r) for r in remediation.references)
            parts.append(f'<p><strong>References:</strong> {ref_list}</p>')
        return "\n".join(parts)

    def _render_finding_compliance(self, finding: ProfessionalFinding) -> str:
        rows = ""
        for framework, mapping in finding.compliance_mapping.items():
            if mapping and mapping != "Not mapped":
                rows += f'<tr><td>{_e(framework)}</td><td>{_e(mapping)}</td></tr>'
        if not rows:
            return ""
        return (
            '<h3>Compliance Mapping</h3>'
            '<table class="mini-table"><thead><tr><th>Framework</th><th>Mapping</th></tr></thead>'
            f'<tbody>{rows}</tbody></table>'
        )

    def _render_references_section(self, references: list) -> str:
        rows = []
        for ref in references:
            fw = getattr(ref, "framework", "")
            cat_id = getattr(ref, "category_id", "")
            cat_name = getattr(ref, "category_name", "")
            url = getattr(ref, "url", "")
            cat_display = f'<a href="{_e(url)}" target="_blank">{_e(cat_id)}</a>' if url else _e(cat_id)
            rows.append(f'<tr><td>{_e(fw)}</td><td>{cat_display}</td><td>{_e(cat_name)}</td></tr>')
        if rows:
            return (
                '<h3>Taxonomy References</h3>'
                '<table><thead><tr><th>Framework</th><th>ID</th><th>Name</th></tr></thead>'
                f'<tbody>{"".join(rows)}</tbody></table>'
            )
        return ""

    def _render_attack_chains(self, report: DeveloperReport) -> str:
        chains_html = []
        for chain in report.attack_chains:
            steps_html = []
            for step in chain.steps:
                mitre = f" | MITRE: {_e(step.mitre_id)}" if step.mitre_id else ""
                phase = f" | Phase: {_e(step.attack_phase)}" if step.attack_phase else ""
                steps_html.append(
                    f'<div class="chain-step">'
                    f'<div class="step-number">{step.step_number}</div>'
                    f'<div><strong>{_e(step.title)}</strong> '
                    f'({_e(str(step.severity))})<br>'
                    f'{_e(step.description)}<br>'
                    f'<em>Entry: {_e(step.entry_point)} | Technique: {_e(step.technique)}{mitre}{phase}</em>'
                    f'</div></div>'
                )
            mitre_map = ""
            if chain.mitre_attack_mapping:
                mitre_map = f'<p><strong>MITRE ATT&CK Mapping:</strong> {", ".join(_e(m) for m in chain.mitre_attack_mapping)}</p>'
            kill_chain = ""
            if chain.kill_chain_phases:
                kill_chain = f'<p><strong>Kill Chain Phases:</strong> {" &rarr; ".join(_e(p) for p in chain.kill_chain_phases)}</p>'
            chains_html.append(
                f'<div class="attack-chain">'
                f'<h3>{_e(chain.title)}</h3>'
                f'<p>{_e(chain.description)}</p>'
                f'<div>{"".join(steps_html)}</div>'
                f'{mitre_map}{kill_chain}'
                f'<p><strong>Final Impact:</strong> {_e(chain.final_impact)}</p>'
                f'<p><strong>Mitigation:</strong> {_e(chain.mitigation_summary)}</p>'
                f'</div>'
            )
        return (
            f'<div class="page" id="attack-chains"><h2>7. Attack Chains</h2>'
            f'{"".join(chains_html)}</div>'
        )

    def _render_root_cause_analysis(self, report: DeveloperReport) -> str:
        groups = report.root_cause_groupings or report.metadata.root_cause_groupings
        if not groups:
            return ""
        cards = []
        for g in groups:
            if isinstance(g, RootCauseGrouping):
                cards.append(
                    f'<div class="root-cause-card">'
                    f'<h4>{_e(g.root_cause)}</h4>'
                    f'<p><strong>Affected Findings:</strong> {g.affected_finding_count} ({_e(", ".join(g.affected_findings[:3]))}{"..." if len(g.affected_findings) > 3 else ""})</p>'
                    f'<p><strong>Business Risk:</strong> {_e(g.business_risk)}</p>'
                    f'<p><strong>Recommended Master Fix:</strong> {_e(g.recommended_master_fix)}</p></div>'
                )
            elif isinstance(g, dict):
                cards.append(
                    f'<div class="root-cause-card">'
                    f'<h4>{_e(g.get("root_cause", ""))}</h4>'
                    f'<p><strong>Affected Findings:</strong> {g.get("affected_finding_count", 0)}</p>'
                    f'<p><strong>Business Risk:</strong> {_e(g.get("business_risk", ""))}</p>'
                    f'<p><strong>Recommended Master Fix:</strong> {_e(g.get("recommended_master_fix", ""))}</p></div>'
                )
        return f'<div class="page" id="root-cause"><h2>8. Root Cause Analysis</h2>{"".join(cards)}</div>'

    def _render_sbom_summary(self, report: DeveloperReport) -> str:
        entries = report.sbom_entries or report.metadata.sbom_entries
        if not entries:
            return ""
        rows = ""
        for e in entries:
            if isinstance(e, SBOMEntry):
                pin = "Pinned" if e.pinned else "Unpinned"
                dep_risk = "High" if e.vulnerability_count > 0 else e.risk_level
                rows += (
                    f'<tr><td>{_e(e.package_name)}</td><td>{_e(e.version)}</td>'
                    f'<td>{_e(pin)}</td><td>{_e(e.source)}</td>'
                    f'<td><span class="severity-badge {dep_risk.lower()}">{_e(dep_risk)}</span></td></tr>'
                )
            elif isinstance(e, dict):
                rows += (
                    f'<tr><td>{_e(e.get("package_name", ""))}</td><td>{_e(e.get("version", ""))}</td>'
                    f'<td>{"Pinned" if e.get("pinned") else "Unpinned"}</td>'
                    f'<td>{_e(e.get("source", ""))}</td>'
                    f'<td>{_e(e.get("risk_level", "Low"))}</td></tr>'
                )
        return (
            f'<div class="page" id="sbom"><h2>9. SBOM Summary</h2>'
            '<table><thead><tr><th>Package</th><th>Version</th><th>Pinned</th><th>Source</th><th>Risk</th></tr></thead>'
            f'<tbody>{rows}</tbody></table></div>'
        )

    def _render_compliance_mapping(self, report: DeveloperReport) -> str:
        mappings = report.compliance_mappings or report.metadata.compliance_mappings
        if not mappings:
            return ""
        cards = []
        for cm in mappings:
            if isinstance(cm, ComplianceFrameworkMapping):
                pct = cm.compliance_percentage
            elif isinstance(cm, dict):
                pct = cm.get("compliance_percentage", 0)
                cm = type("CM", (), cm)()
            else:
                continue
            color = "#dc2626" if pct < 50 else "#d97706" if pct < 80 else "#16a34a"
            fw_name = getattr(cm, "framework_name", "")
            fw_ver = getattr(cm, "framework_version", "")
            gaps = getattr(cm, "gaps", [])
            gap_html = ""
            if gaps:
                gap_items = "".join(f"<li>{_e(g)}</li>" for g in gaps[:5])
                gap_html = f'<ul class="small-text">{gap_items}</ul>'
            cards.append(
                f'<div class="compliance-card"><h4>{_e(fw_name)} {_e(fw_ver)}</h4>'
                f'<div class="compliance-bar"><div class="compliance-fill" style="width:{pct:.0f}%;background:{color};"></div></div>'
                f'<p><strong>{pct:.1f}%</strong> compliant</p>{gap_html}</div>'
            )
        return f'<div class="page" id="compliance"><h2>10. Compliance Mapping</h2><div class="compliance-grid">{"".join(cards)}</div></div>'

    def _render_phased_remediation_roadmap(self, report: DeveloperReport) -> str:
        phases = report.remediation_phases or report.metadata.remediation_phases
        if not phases:
            return self._render_simple_remediation(report)
        phase_css = {"Phase 1": "phase1", "Phase 2": "phase2", "Phase 3": "phase3", "Phase 4": "phase4"}
        parts = [f'<div class="page" id="remediation-roadmap"><h2>11. Remediation Roadmap</h2>']
        for phase_name, items in phases.items():
            css_key = next((k for k in phase_css if k in phase_name), "phase1")
            rows = ""
            for item in items:
                if isinstance(item, dict):
                    title = item.get("title", "")
                    sev = item.get("severity", "Info")
                    effort = item.get("effort_hours", 0)
                    rem = item.get("remediation", "")
                    sev_class = sev.lower() if isinstance(sev, str) else "info"
                    rows += (
                        f'<tr><td><span class="severity-badge {sev_class}">{_e(str(sev).upper())}</span></td>'
                        f'<td>{_e(title)}</td><td>{effort:.1f}h</td><td>{_e(rem[:100])}</td></tr>'
                    )
            if rows:
                parts.append(
                    f'<div class="phase-section">'
                    f'<div class="phase-header {phase_css[css_key]}">{_e(phase_name)} ({len(items)} items)</div>'
                    f'<div class="phase-body"><table><thead><tr><th>Severity</th><th>Title</th><th>Effort</th><th>Remediation</th></tr></thead>'
                    f'<tbody>{rows}</tbody></table></div></div>'
                )
        parts.append('</div>')
        return "\n".join(parts)

    def _render_simple_remediation(self, report: DeveloperReport) -> str:
        items = []
        for i, rm in enumerate(report.remediation_roadmap, 1):
            sev = rm.get("severity", "Info")
            sev_class = sev.lower() if isinstance(sev, str) else "info"
            effort = rm.get("effort_hours", 0)
            items.append(
                f'<div class="remediation-item" style="border-left-color:var(--{sev_class});">'
                f'<strong>{i}. [{_e(str(sev).upper())}] {_e(rm.get("title", ""))}</strong><br>'
                f'{_e(rm.get("remediation", ""))}'
                f'<br><em>Complexity: {_e(rm.get("complexity", "Medium"))} | Effort: {effort:.1f}h</em></div>'
            )
        return f'<div class="page" id="remediation-roadmap"><h2>11. Remediation Roadmap</h2>{"".join(items)}</div>'

    def _render_developer_fix_guidance(self, report: DeveloperReport) -> str:
        findings_with_code = [f for f in report.findings if f.code_snippet_vulnerable or f.code_snippet_fixed]
        if not findings_with_code:
            return ""
        cards = []
        for f in findings_with_code[:10]:
            if f.code_snippet_vulnerable and f.code_snippet_fixed:
                cards.append(
                    f'<div class="finding-card">'
                    f'<h4>{_e(f.title)} ({_e(f.file_path)}:{f.line_number})</h4>'
                    '<div class="code-fix">'
                    '<div class="vulnerable"><div class="label">Vulnerable Code</div>'
                    f'<pre>{_e(f.code_snippet_vulnerable)}</pre></div>'
                    '<div class="fixed"><div class="label">Fixed Code</div>'
                    f'<pre>{_e(f.code_snippet_fixed)}</pre></div></div></div>'
                )
        return f'<div class="page" id="fix-guidance"><h2>12. Developer Fix Guidance</h2>{"".join(cards)}</div>'

    def _render_assessment_limitations(self, report: DeveloperReport) -> str:
        limitations = report.assessment_limitations or report.metadata.assessment_limitations
        items = []
        for lim in limitations:
            if isinstance(lim, AssessmentLimitation):
                items.append(
                    f'<div class="limitation-item">'
                    f'<strong>{_e(lim.category)}</strong><br>'
                    f'{_e(lim.description)}<br>'
                    f'<em>Impact:</em> {_e(lim.impact)}<br>'
                    f'<em>Recommendation:</em> {_e(lim.recommendation)}</div>'
                )
            elif isinstance(lim, dict):
                items.append(
                    f'<div class="limitation-item">'
                    f'<strong>{_e(lim.get("category", ""))}</strong><br>'
                    f'{_e(lim.get("description", ""))}<br>'
                    f'<em>Impact:</em> {_e(lim.get("impact", ""))}<br>'
                    f'<em>Recommendation:</em> {_e(lim.get("recommendation", ""))}</div>'
                )
        validation_notes = report.metadata.scanner_validation_notes
        notes_html = ""
        if validation_notes:
            note_items = "".join(f'<div class="validation-note">{_e(n)}</div>' for n in validation_notes)
            notes_html = f'<h3>Scanner Validation Notes</h3>{note_items}'
        manual_recs = report.manual_review_recommendations or report.metadata.manual_review_recommendations
        manual_html = ""
        if manual_recs:
            rec_items = "".join(f"<li>{_e(r)}</li>" for r in manual_recs)
            manual_html = f'<h3>Manual Review Recommendations</h3><ul class="kb-list">{rec_items}</ul>'
        return (
            f'<div class="page" id="limitations"><h2>13. Assessment Limitations &amp; Credibility</h2>'
            f'{" ".join(items)}{notes_html}{manual_html}'
            f'<p class="small-text"><strong>Validation Status:</strong> {_e(report.metadata.validation_status)}</p></div>'
        )

    def _render_security_posture_section(self, report: DeveloperReport) -> str:
        scores = report.security_posture_scores or report.metadata.security_posture_scores

        def full_card(label: str, score: float) -> str:
            color = "#dc2626" if score < 40 else "#ea580c" if score < 70 else "#16a34a"
            return (
                f'<div class="posture-full-card">'
                f'<div class="posture-full-score" style="color:{color};">{score:.0f}</div>'
                f'<div class="posture-full-label">{_e(label)}</div></div>'
            )
        cards = ""
        for label, val in [
            ("Overall Security Maturity", scores.overall_score),
            ("Application Security", scores.application_security_score),
            ("Supply Chain Security", scores.supply_chain_score),
            ("Secrets Management", scores.secrets_management_score),
            ("Dependency Hygiene", scores.dependency_hygiene_score),
            ("Logging Maturity", scores.logging_maturity_score),
        ]:
            cards += full_card(label, val)
        gap_html = ""
        if scores.gap_analysis:
            gap_html = f'<div class="exec-section"><h3>Gap Analysis</h3><p>{_e(scores.gap_analysis)}</p></div>'
        current_target = ""
        if scores.current_state or scores.target_state:
            current_target = (
                '<div class="exec-section"><h3>Current vs Target State</h3>'
                f'<p><strong>Current:</strong> {_e(scores.current_state) or "N/A"}</p>'
                f'<p><strong>Target:</strong> {_e(scores.target_state) or "N/A"}</p></div>'
            )
        return (
            f'<div class="page" id="posture"><h2>14. Final Security Posture</h2>'
            f'<div class="posture-full">{cards}</div>{gap_html}{current_target}</div>'
        )

    def _render_appendix(self, report: DeveloperReport) -> str:
        meta = report.metadata
        scan = meta.scan_metadata
        rows = [
            f'<tr><td><strong>Report Type</strong></td><td>{_e(meta.report_type)}</td></tr>',
            f'<tr><td><strong>Classification</strong></td><td>{_e(meta.classification)}</td></tr>',
            f'<tr><td><strong>Scanner</strong></td><td>{_e(scan.scanner_name)} v{_e(scan.scanner_version)}</td></tr>',
            f'<tr><td><strong>Scan ID</strong></td><td>{_e(scan.scan_id)}</td></tr>',
            f'<tr><td><strong>Target</strong></td><td>{_e(scan.target_path)}</td></tr>',
            f'<tr><td><strong>Duration</strong></td><td>{scan.duration_seconds:.1f}s</td></tr>',
            f'<tr><td><strong>Files Scanned</strong></td><td>{scan.files_scanned}</td></tr>',
            f'<tr><td><strong>Total Findings</strong></td><td>{meta.total_findings}</td></tr>',
            f'<tr><td><strong>Risk Score</strong></td><td>{meta.risk_score:.1f}/10</td></tr>',
        ]
        known = report.known_assumptions or meta.known_assumptions
        if known:
            items = "".join(f"<li>{_e(a)}</li>" for a in known)
            rows.append(f'<tr><td><strong>Known Assumptions</strong></td><td><ul class="kb-list">{items}</ul></td></tr>')
        return (
            f'<div class="page" id="appendix"><h2>15. Appendix</h2>'
            '<table>' + "".join(rows) + '</table>'
            '<div class="footer">'
            '<p>Generated by CodeSentinelX Enterprise Security Scanner | ' + _e(meta.generated_at or _now_iso()) + '</p>'
            '<p>This report is confidential and intended for authorized recipients only.</p>'
            '<p>Automated scan with manual review recommended for complete assurance.</p>'
            '</div></div>'
        )

    def _severity_counts(self, report: DeveloperReport) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in report.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts
