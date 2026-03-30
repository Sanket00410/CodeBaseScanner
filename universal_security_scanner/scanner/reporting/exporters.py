from __future__ import annotations

import base64
import html
import json
from datetime import datetime
from pathlib import Path
import re
import textwrap


SEVERITY_ORDER = {
    "Critical": 0,
    "High": 1,
    "Medium": 2,
    "Low": 3,
    "Info": 4,
}

_REPORT_GLOBE_TEXTURE_CACHE: str | None = None


def _report_globe_texture_data_uri() -> str:
    global _REPORT_GLOBE_TEXTURE_CACHE
    if _REPORT_GLOBE_TEXTURE_CACHE is not None:
        return _REPORT_GLOBE_TEXTURE_CACHE
    asset_path = Path(__file__).resolve().parents[3] / "SecureScope" / "frontend" / "public" / "earth-night-texture.jpg"
    if not asset_path.exists():
        _REPORT_GLOBE_TEXTURE_CACHE = ""
        return _REPORT_GLOBE_TEXTURE_CACHE
    try:
        _REPORT_GLOBE_TEXTURE_CACHE = (
            "data:image/jpeg;base64," + base64.b64encode(asset_path.read_bytes()).decode("ascii")
        )
    except OSError:
        _REPORT_GLOBE_TEXTURE_CACHE = ""
    return _REPORT_GLOBE_TEXTURE_CACHE


def _report_globe_css() -> str:
    texture = _report_globe_texture_data_uri()
    globe_background = (
        f'url("{texture}")'
        if texture
        else "radial-gradient(circle at 35% 35%, rgba(164, 224, 255, 0.18), rgba(14, 33, 54, 0.88) 58%, rgba(2, 8, 14, 1) 100%)"
    )
    return f"""
    body {{
      position: relative;
      overflow-x: hidden;
    }}
    body::before {{
      content: "";
      position: fixed;
      right: -7vw;
      top: -4vh;
      width: min(58vw, 840px);
      aspect-ratio: 1;
      border-radius: 50%;
      background-image: {globe_background};
      background-repeat: repeat-x;
      background-size: auto 100%;
      background-position: 36% 50%;
      box-shadow: inset -58px -30px 118px rgba(0,0,0,0.62), inset 22px 18px 30px rgba(92,209,255,0.06), 0 28px 84px rgba(0,0,0,0.42);
      border: 1px solid rgba(110,226,255,0.22);
      opacity: 0.44;
      filter: saturate(1.16) contrast(1.22) brightness(1.06);
      animation: reportGlobeSpin 88s linear infinite;
      pointer-events: none;
      z-index: 0;
    }}
    body::after {{
      content: "";
      position: fixed;
      right: -3vw;
      top: 6vh;
      width: min(49vw, 700px);
      aspect-ratio: 1;
      border-radius: 50%;
      background: radial-gradient(circle at 36% 34%, rgba(154,224,255,0.16), transparent 34%), radial-gradient(circle at center, rgba(14,31,52,0.2), transparent 68%);
      box-shadow: 0 0 48px rgba(53,209,255,0.14), inset 0 0 22px rgba(105,214,255,0.08);
      opacity: 0.5;
      pointer-events: none;
      z-index: 0;
    }}
    body > * {{
      position: relative;
      z-index: 1;
    }}
    @keyframes reportGlobeSpin {{
      from {{ background-position: 36% 50%; }}
      to {{ background-position: -164% 50%; }}
    }}
    @media print {{
      body {{
        background: #071321;
        color: #dce9f7;
      }}
      body::before {{
        animation: none;
        right: -8px;
        top: 8px;
        width: 420px;
        opacity: 0.3;
        border-color: rgba(110,226,255,0.18);
        filter: saturate(1.1) contrast(1.15) brightness(0.9);
      }}
      body::after {{
        right: 12px;
        top: 28px;
        width: 340px;
        opacity: 0.18;
      }}
    }}
    """


def _as_dict(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _display_report_tool_name(tool: object) -> str:
    value = str(tool or "").strip()
    if not value:
        return "CodeSentinelX"
    normalized = value.lower()
    if normalized in {"scanner", "codebasescanner", "codesentinelx", "universal security scanner", "universal_security_scanner"}:
        return "CodeSentinelX"
    return value


def _quality_benchmark_from_report(report: dict) -> dict[str, Any] | None:
    executive = _as_dict(report.get("executive_summary"))
    existing = _as_dict(report.get("existing_implementation_report"))
    vuln = _as_dict(report.get("vulnerability_fixed_code_report"))
    candidates = [
        _as_dict(executive.get("data_quality")).get("quality_benchmark"),
        _as_dict(executive.get("enterprise_assurance")).get("quality_benchmark"),
        _as_dict(vuln.get("summary")).get("data_quality", {}).get("quality_benchmark") if isinstance(_as_dict(vuln.get("summary")).get("data_quality"), dict) else None,
        _as_dict(vuln.get("summary")).get("enterprise_assurance", {}).get("quality_benchmark") if isinstance(_as_dict(vuln.get("summary")).get("enterprise_assurance"), dict) else None,
        _as_dict(existing.get("summary")).get("quality_benchmark"),
    ]
    for benchmark in candidates:
        if isinstance(benchmark, dict) and benchmark.get("configured"):
            return benchmark
    return None


def _render_quality_benchmark_html_section(report: dict) -> str:
    benchmark = _quality_benchmark_from_report(report)
    if not benchmark:
        return ""
    rows = [
        ("Benchmark Status", str(benchmark.get("benchmark_status", "warning")).upper()),
        ("Benchmark Name", str(benchmark.get("benchmark_name", "Scanner Quality Benchmark"))),
        ("Benchmark File", str(benchmark.get("benchmark_file", "N/A"))),
        ("Description", str(benchmark.get("benchmark_description", "N/A")) or "N/A"),
        (
            "Cases",
            f"{int(benchmark.get('cases_total', 0))} total ({int(benchmark.get('expected_present', 0))} expected-present, {int(benchmark.get('expected_absent', 0))} expected-absent)",
        ),
        ("Precision", f"{float(benchmark.get('precision_percent', 0.0)):.2f}%"),
        ("Recall", f"{float(benchmark.get('recall_percent', 0.0)):.2f}%"),
        ("F1", f"{float(benchmark.get('f1_percent', 0.0)):.2f}%"),
        ("False Positive Rate", f"{float(benchmark.get('false_positive_rate_percent', 0.0)):.2f}%"),
        (
            "Thresholds",
            "precision >= "
            f"{float(benchmark.get('threshold_precision_percent', 0.0)):.2f}%, "
            f"recall >= {float(benchmark.get('threshold_recall_percent', 0.0)):.2f}%, "
            f"f1 >= {float(benchmark.get('threshold_f1_percent', 0.0)):.2f}%",
        ),
        ("True Positives", str(int(benchmark.get("true_positives", 0)))),
        ("False Positives", str(int(benchmark.get("false_positives", 0)))),
        ("False Negatives", str(int(benchmark.get("false_negatives", 0)))),
        ("True Negatives", str(int(benchmark.get("true_negatives", 0)))),
    ]
    blocker_items = "".join(f"<li>{html.escape(str(item))}</li>" for item in (benchmark.get("gate_blockers") or [])[:4])
    advisory_items = "".join(f"<li>{html.escape(str(item))}</li>" for item in (benchmark.get("gate_advisories") or [])[:4])
    rows_html = "".join(
        f"<tr><td>{html.escape(str(key))}</td><td>{html.escape(str(value))}</td></tr>"
        for key, value in rows
    )
    return f"""
    <section class="table-frame">
      <h2 style="padding:12px 14px 0">Scanner Quality Benchmark</h2>
      <div class="table-scroll">
        <table>
          <thead><tr><th>Metric</th><th>Value</th></tr></thead>
          <tbody>{rows_html}</tbody>
        </table>
      </div>
      {"<div style='padding:0 14px 14px'><h3>Benchmark Blockers</h3><ul>{}</ul></div>".format(blocker_items) if blocker_items else ""}
      {"<div style='padding:0 14px 14px'><h3>Benchmark Advisories</h3><ul>{}</ul></div>".format(advisory_items) if advisory_items else ""}
    </section>
    """


def _sanitize_export_token(value: str, fallback: str) -> str:
    normalized = str(value or "").strip().replace("\\", "/")
    normalized = re.sub(r"^[A-Za-z]:", "", normalized).strip("/")
    token = re.sub(r"[^A-Za-z0-9._-]+", "-", normalized)
    token = re.sub(r"-+", "-", token).strip("-_.")
    return token or fallback


def _extract_export_target_name(report: dict) -> str:
    candidates = [
        report.get("vulnerability_fixed_code_report", {}).get("target_path"),
        report.get("existing_implementation_report", {}).get("target_path"),
        report.get("executive_summary", {}).get("target_path"),
    ]
    for raw in candidates:
        candidate = str(raw or "").strip()
        if not candidate:
            continue
        normalized = candidate.replace("\\", "/")
        if normalized.startswith(("http://", "https://", "ssh://")):
            without_scheme = normalized.split("://", 1)[1]
            host, _, path_part = without_scheme.partition("/")
            segments = [segment for segment in path_part.split("/") if segment]
            return _sanitize_export_token(segments[-1] if segments else host, "target")
        segments = [segment for segment in normalized.split("/") if segment]
        if segments:
            return _sanitize_export_token(segments[-1], "target")
    return "target"


def _extract_export_date_time(value: str) -> tuple[str, str]:
    raw = str(value or "").strip()
    if raw:
        normalized = raw.replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(normalized)
            return parsed.strftime("%Y-%m-%d"), parsed.strftime("%H-%M-%S-%f")[:12]
        except ValueError:
            pass
    match = re.search(r"(\d{4}-\d{2}-\d{2}).*?(\d{2})[:\-](\d{2})[:\-](\d{2})(?:[.\-:](\d{1,3}))?", raw)
    if match:
        date_part = match.group(1)
        time_part = "-".join(part for part in match.groups()[1:] if part)
        return date_part, time_part
    safe = raw.replace(":", "-").replace(".", "-").replace("T", "_")
    date_raw, _, time_raw = safe.partition("_")
    return _sanitize_export_token(date_raw or "date", "date"), _sanitize_export_token(time_raw or "time", "time")


def _format_display_timestamp(value: str) -> str:
    raw = str(value or "").strip()
    if not raw:
        return "N/A"
    normalized = raw.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
        return parsed.strftime("%Y-%m-%d %H:%M:%S.%f")[:23]
    except ValueError:
        return raw


def _severity_rank(value: str) -> int:
    return SEVERITY_ORDER.get(value, 99)


def _vulnerability_findings(report: dict) -> list[dict]:
    vuln_report = report.get("vulnerability_fixed_code_report", {})
    findings = vuln_report.get("findings")
    if isinstance(findings, list):
        return findings
    return report.get("technical_report", {}).get("findings", [])


def _sorted_findings(report: dict) -> list[dict]:
    findings = _vulnerability_findings(report)
    return sorted(
        findings,
        key=lambda item: (
            _severity_rank(str(item.get("severity", "Info"))),
            -float(item.get("cvss_score", 0.0)),
            str(item.get("file_path", "")),
            int(item.get("line_number", 0)),
        ),
    )


def _normalize_path(value: str) -> str:
    return str(value or "").replace("\\", "/")


def _folder_name(file_path: str) -> str:
    normalized = _normalize_path(file_path)
    if not normalized:
        return "."
    if normalized.startswith("http://") or normalized.startswith("https://"):
        scheme, _, rest = normalized.partition("://")
        host, _, path = rest.partition("/")
        if not path:
            return f"{scheme}://{host}"
        folder = path.rsplit("/", 1)[0] if "/" in path else ""
        return f"{scheme}://{host}/{folder}" if folder else f"{scheme}://{host}"
    if normalized.startswith("ssh://"):
        without = normalized.split("://", 1)[1]
        host, _, path = without.partition("/")
        if not path:
            return f"ssh://{host}"
        folder = path.rsplit("/", 1)[0] if "/" in path else ""
        return f"ssh://{host}/{folder}" if folder else f"ssh://{host}"
    if "/" not in normalized:
        return "."
    return normalized.rsplit("/", 1)[0] or "."


def _affected_files(findings: list[dict], limit: int = 80) -> list[dict]:
    counters: dict[str, dict[str, int | str]] = {}
    for finding in findings:
        file_path = _normalize_path(str(finding.get("file_path", "unknown")))
        if file_path not in counters:
            counters[file_path] = {
                "file": file_path,
                "folder": _folder_name(file_path),
                "count": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0,
            }
        row = counters[file_path]
        row["count"] = int(row["count"]) + 1
        severity = str(finding.get("severity", "Info"))
        if severity == "Critical":
            row["critical"] = int(row["critical"]) + 1
        elif severity == "High":
            row["high"] = int(row["high"]) + 1
        elif severity == "Medium":
            row["medium"] = int(row["medium"]) + 1
        elif severity == "Low":
            row["low"] = int(row["low"]) + 1
        else:
            row["info"] = int(row["info"]) + 1
    rows = sorted(counters.values(), key=lambda item: int(item["count"]), reverse=True)
    return rows[:limit]


def _affected_folders(findings: list[dict], limit: int = 40) -> list[dict]:
    counters: dict[str, dict[str, int | str]] = {}
    for finding in findings:
        folder = _folder_name(str(finding.get("file_path", "unknown")))
        if folder not in counters:
            counters[folder] = {
                "folder": folder,
                "count": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0,
            }
        row = counters[folder]
        row["count"] = int(row["count"]) + 1
        severity = str(finding.get("severity", "Info"))
        if severity == "Critical":
            row["critical"] = int(row["critical"]) + 1
        elif severity == "High":
            row["high"] = int(row["high"]) + 1
        elif severity == "Medium":
            row["medium"] = int(row["medium"]) + 1
        elif severity == "Low":
            row["low"] = int(row["low"]) + 1
        else:
            row["info"] = int(row["info"]) + 1
    rows = sorted(counters.values(), key=lambda item: int(item["count"]), reverse=True)
    return rows[:limit]


def _owasp_counts(findings: list[dict], limit: int = 20) -> list[dict]:
    counts: dict[str, int] = {}
    for finding in findings:
        key = str(finding.get("owasp_mapping") or finding.get("owasp_category") or "N/A")
        counts[key] = counts.get(key, 0) + 1
    rows = [{"owasp_category": key, "count": count} for key, count in counts.items()]
    rows.sort(key=lambda item: int(item["count"]), reverse=True)
    return rows[:limit]


def _alert_groups(findings: list[dict]) -> list[dict]:
    grouped: dict[tuple[str, str, str], dict] = {}
    for finding in findings:
        title = str(finding.get("vulnerability_title") or finding.get("vulnerability_type") or "Issue")
        cwe = str(finding.get("cwe_id") or finding.get("cwe") or "N/A")
        owasp = str(finding.get("owasp_mapping") or finding.get("owasp_category") or "N/A")
        key = (title, cwe, owasp)
        if key not in grouped:
            grouped[key] = {
                "id": _slugify(f"{title}-{cwe}-{owasp}"),
                "title": title,
                "severity": str(finding.get("severity", "Info")),
                "cwe": cwe,
                "owasp": owasp,
                "count": 0,
                "findings": [],
            }
        entry = grouped[key]
        entry["count"] += 1
        entry["findings"].append(finding)
        if _severity_rank(str(finding.get("severity", "Info"))) < _severity_rank(entry["severity"]):
            entry["severity"] = str(finding.get("severity", "Info"))

    rows = list(grouped.values())
    rows.sort(key=lambda item: (_severity_rank(str(item["severity"])), -int(item["count"])))
    return rows


def _fix_verification_summary(findings: list[dict]) -> dict[str, int]:
    summary = {
        "performed": 0,
        "verified_fixed": 0,
        "verification_failed": 0,
        "inconclusive": 0,
        "not_applicable": 0,
        "skipped": 0,
        "build_verified": 0,
        "build_failed": 0,
        "test_verified": 0,
        "test_failed": 0,
    }
    for item in findings:
        verification = item.get("fix_verification") or {}
        if verification.get("performed"):
            summary["performed"] += 1
        result = str(verification.get("result") or "").strip().lower()
        if result == "verified_fixed":
            summary["verified_fixed"] += 1
        elif result in {"verification_failed", "still_vulnerable"}:
            summary["verification_failed"] += 1
        elif result in {"manual_review_required", "inconclusive"}:
            summary["inconclusive"] += 1
        elif result == "skipped":
            summary["skipped"] += 1
        else:
            summary["not_applicable"] += 1
        build_verification = verification.get("build_verification") or {}
        if str(build_verification.get("status") or "").lower() == "success":
            summary["build_verified"] += 1
        elif build_verification:
            summary["build_failed"] += 1
        test_verification = verification.get("test_verification") or {}
        if str(test_verification.get("status") or "").lower() == "success":
            summary["test_verified"] += 1
        elif test_verification:
            summary["test_failed"] += 1
    return summary


def _dependency_auth_summary(item: dict) -> str:
    reachability = item.get("dependency_reachability") or {}
    if not reachability:
        return ""
    parts = [
        f"status={reachability.get('status', 'unknown')}",
        f"manifest={'yes' if reachability.get('manifest_present') else 'no'}",
        f"lockfile={'yes' if reachability.get('lockfile_present') else 'no'}",
        f"advisory_verified={'yes' if reachability.get('advisory_verified', True) else 'no'}",
    ]
    declared = ", ".join((reachability.get("declared_versions") or [])[:2])
    locked = ", ".join((reachability.get("locked_versions") or [])[:2])
    imports = ", ".join((reachability.get("import_evidence") or [])[:2])
    if declared:
        parts.append(f"declared={declared}")
    if locked:
        parts.append(f"locked={locked}")
    if imports:
        parts.append(f"imports={imports}")
    return " | ".join(parts)


def _dependency_auth_detail(item: dict) -> str:
    reachability = item.get("dependency_reachability") or {}
    if not reachability:
        return ""
    parts = [
        f"Manifest paths: {', '.join((reachability.get('manifest_paths') or [])[:3])}" if reachability.get("manifest_paths") else "",
        f"Lockfile paths: {', '.join((reachability.get('lockfile_paths') or [])[:3])}" if reachability.get("lockfile_paths") else "",
        f"Advisories: {', '.join((reachability.get('advisory_ids') or [])[:4])}" if reachability.get("advisory_ids") else "",
        str(reachability.get("reasoning") or "").strip(),
    ]
    return " | ".join(part for part in parts if part)


def _slugify(value: str) -> str:
    parts: list[str] = []
    for char in value.lower():
        if char.isalnum():
            parts.append(char)
        elif parts and parts[-1] != "-":
            parts.append("-")
    slug = "".join(parts).strip("-")
    return slug[:80] if slug else "alert"


class ReportExporter:
    def __init__(self, export_dir: Path) -> None:
        self.export_dir = export_dir

    def _ensure_export_dir(self) -> Path:
        self.export_dir.mkdir(parents=True, exist_ok=True)
        return self.export_dir

    def _select_payload(self, report: dict, report_type: str) -> dict:
        normalized = report_type.lower()
        if normalized == "existing":
            return {
                "scanner": report.get("scanner", {}),
                "executive_summary": report.get("executive_summary", {}),
                "existing_implementation_report": report.get("existing_implementation_report", {}),
            }
        if normalized == "vulnerability":
            return {
                "scanner": report.get("scanner", {}),
                "executive_summary": report.get("executive_summary", {}),
                "vulnerability_fixed_code_report": report.get("vulnerability_fixed_code_report", {}),
            }
        if normalized == "fixes":
            findings = _sorted_findings(report)
            return {
                "scanner": report.get("scanner", {}),
                "executive_summary": report.get("executive_summary", {}),
                "original_suggested_fix_report": {
                    "title": "CodeSentinelX Original and Suggested Fix Report",
                    "target_path": report.get("vulnerability_fixed_code_report", {}).get(
                        "target_path", report.get("executive_summary", {}).get("target_path", "N/A")
                    ),
                    "generated_at": report.get("vulnerability_fixed_code_report", {}).get(
                        "generated_at", report.get("executive_summary", {}).get("generated_at", "N/A")
                    ),
                    "total_findings": len(findings),
                    "findings": findings,
                },
            }
        return report

    def export_json(self, report: dict, output_path: Path, report_type: str = "combined") -> Path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        payload = self._select_payload(report, report_type)
        output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return output_path

    def export_html(self, report: dict, output_path: Path, report_type: str = "combined") -> Path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(self._render_html(report, report_type), encoding="utf-8")
        return output_path

    def export_pdf(self, report: dict, output_path: Path, report_type: str = "combined") -> Path:
        html_payload = self._render_html(report, report_type)
        try:  # Prefer HTML-to-PDF so exported PDF mirrors dashboard layout.
            from weasyprint import HTML

            output_path.parent.mkdir(parents=True, exist_ok=True)
            HTML(string=html_payload, base_url=str(output_path.parent)).write_pdf(str(output_path))
            return output_path
        except ModuleNotFoundError:
            pass
        except Exception:
            # Fall back to reportlab text renderer when HTML renderer is unavailable.
            pass

        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.pdfgen import canvas
        except ModuleNotFoundError as exc:  # pragma: no cover - dependency-based branch
            raise RuntimeError(
                "PDF export requires 'reportlab'. Install dependencies with: pip install -e ."
            ) from exc

        output_path.parent.mkdir(parents=True, exist_ok=True)

        pdf = canvas.Canvas(str(output_path), pagesize=A4)
        _, height = A4
        x_margin = 30
        y = height - 32

        def write_line(text: str, font: str = "Helvetica", size: int = 9, gap: int = 12) -> None:
            nonlocal y
            if y <= 36:
                pdf.showPage()
                y = height - 32
            pdf.setFont(font, size)
            pdf.drawString(x_margin, y, text[:130])
            y -= gap

        def write_block(text: str, font: str = "Helvetica", size: int = 8, gap: int = 10, width: int = 115) -> None:
            lines = textwrap.wrap(str(text or ""), width=width) or [""]
            for line in lines:
                write_line(line, font=font, size=size, gap=gap)

        def write_quality_benchmark_section() -> None:
            benchmark = _quality_benchmark_from_report(report)
            if not benchmark or not benchmark.get("configured"):
                return
            write_line("Scanner Quality Benchmark", font="Helvetica-Bold", size=11)
            write_line(
                f"- Status: {str(benchmark.get('benchmark_status', 'warning')).upper()}",
                size=8,
            )
            write_line(f"- Benchmark: {benchmark.get('benchmark_name', 'Scanner Quality Benchmark')}", size=8)
            write_line(
                f"- Cases: {int(benchmark.get('cases_total', 0))} total ({int(benchmark.get('expected_present', 0))} expected-present, {int(benchmark.get('expected_absent', 0))} expected-absent)",
                size=8,
            )
            write_line(f"- Precision: {float(benchmark.get('precision_percent', 0.0)):.2f}%", size=8)
            write_line(f"- Recall: {float(benchmark.get('recall_percent', 0.0)):.2f}%", size=8)
            write_line(f"- F1: {float(benchmark.get('f1_percent', 0.0)):.2f}%", size=8)
            write_line(f"- False Positive Rate: {float(benchmark.get('false_positive_rate_percent', 0.0)):.2f}%", size=8)
            for blocker in (benchmark.get("gate_blockers") or [])[:4]:
                write_line(f"- Blocker: {blocker}", size=8)
            for advisory in (benchmark.get("gate_advisories") or [])[:4]:
                write_line(f"- Advisory: {advisory}", size=8)

        summary = report.get("executive_summary", {})
        report_kind = report_type.lower()

        if report_kind == "existing":
            existing = report.get("existing_implementation_report", {})
            controls = existing.get("controls", [])
            write_line("CodeSentinelX Existing Security Implementation Report", font="Helvetica-Bold", size=13, gap=16)
            write_line(f"Target: {existing.get('target_path', summary.get('target_path', 'N/A'))}")
            write_line(f"Generated: {_format_display_timestamp(str(existing.get('generated_at', summary.get('generated_at', 'N/A'))))}", gap=14)
            write_line("Coverage Summary", font="Helvetica-Bold", size=11)
            for key, value in (existing.get("summary", {}) or {}).items():
                write_line(f"- {key.replace('_', ' ').title()}: {value}")
            write_line("Implemented Controls", font="Helvetica-Bold", size=11)
            for control in controls[:80]:
                write_line(
                    f"- {control.get('name', 'Control')} [{control.get('coverage_level', 'N/A')}] "
                    f"({control.get('category', 'Security')})"
                )
            write_quality_benchmark_section()
            pdf.save()
            return output_path

        if report_kind == "fixes":
            vuln = report.get("vulnerability_fixed_code_report", {})
            findings = _sorted_findings(report)
            verification = _fix_verification_summary(findings)
            write_line("CodeSentinelX Original and Suggested Fix Report", font="Helvetica-Bold", size=13, gap=16)
            write_line(f"Target: {vuln.get('target_path', summary.get('target_path', 'N/A'))}")
            write_line(f"Generated: {_format_display_timestamp(str(vuln.get('generated_at', summary.get('generated_at', 'N/A'))))}")
            write_line(f"Total findings: {len(findings)}", gap=14)
            write_line("Verification Summary", font="Helvetica-Bold", size=11)
            for key, value in verification.items():
                write_line(f"- {key.replace('_', ' ').title()}: {value}", size=8)
            for item in findings[:220]:
                write_line(
                    f"[{item.get('severity', 'Info')}] {item.get('vulnerability_title', item.get('vulnerability_type', 'Issue'))}",
                    font="Helvetica-Bold",
                    size=9,
                )
                write_line(
                    f"Location: {_normalize_path(str(item.get('file_path', 'unknown')))}:{item.get('line_number', 1)}",
                    size=8,
                )
                write_line(
                    f"CWE: {item.get('cwe_id') or item.get('cwe') or 'N/A'} | OWASP: {item.get('owasp_mapping', 'N/A')}",
                    size=8,
                )
                write_line("Recommendation:", size=8)
                write_block(str(item.get("recommendation", "N/A")), size=8)
                dependency_summary = _dependency_auth_summary(item)
                if dependency_summary:
                    write_line(f"Dependency Authenticity: {dependency_summary}", size=8)
                    write_block(_dependency_auth_detail(item), size=8)
                if item.get("fix_verification"):
                    write_line(
                        f"Fix Verification: {item.get('fix_verification', {}).get('result', 'not_applicable')} | {item.get('fix_verification', {}).get('reason', '')}",
                        size=8,
                    )
                    build_info = (item.get("fix_verification") or {}).get("build_verification") or {}
                    if build_info:
                        write_line(f"Workspace Build: {build_info.get('status', 'unknown')} | {build_info.get('command', '')}", size=8)
                        write_block(str(build_info.get("output", "")), size=8)
                    test_info = (item.get("fix_verification") or {}).get("test_verification") or {}
                    if test_info:
                        write_line(f"Workspace Test: {test_info.get('status', 'unknown')} | {test_info.get('command', '')}", size=8)
                        write_block(str(test_info.get("output", "")), size=8)
                write_line("Original Code:", size=8)
                write_block(str(item.get("original_code", "Snippet unavailable.")), font="Courier", size=8)
                write_line("Suggested Fix:", size=8)
                write_block(str(item.get("ai_suggested_fix") or item.get("fixed_code", "No direct fix available.")), font="Courier", size=8)
                write_line("", gap=4)
            if len(findings) > 220:
                write_line(f"Truncated after 220 entries. Additional findings: {len(findings) - 220}", size=8)
            pdf.save()
            return output_path

        findings = _sorted_findings(report)
        vuln = report.get("vulnerability_fixed_code_report", {})
        vuln_summary = vuln.get("summary", {})
        affected_files = _affected_files(findings, limit=30)
        affected_modules = vuln_summary.get("affected_modules", summary.get("affected_modules", [])) or []
        owasp_categories = vuln_summary.get("top_owasp_categories", summary.get("top_owasp_categories", [])) or []
        action_plan = summary.get("recommended_action_plan", []) or []
        alerts = _alert_groups(findings)
        write_line("CodeSentinelX Vulnerability Report (ZAP-Style)", font="Helvetica-Bold", size=13, gap=16)
        write_line(f"Target: {vuln.get('target_path', summary.get('target_path', 'N/A'))}")
        write_line(f"Generated: {_format_display_timestamp(str(vuln.get('generated_at', summary.get('generated_at', 'N/A'))))}")
        write_line(f"Risk Score: {vuln_summary.get('risk_score', summary.get('risk_score', 0))}", gap=14)
        write_line("Summary of Alerts", font="Helvetica-Bold", size=11)
        for severity, count in (vuln_summary.get("severity_distribution", summary.get("severity_distribution", {})) or {}).items():
            write_line(f"- {severity}: {count}")
        write_line("Top Affected Files", font="Helvetica-Bold", size=11)
        for item in affected_files:
            write_line(
                f"- {item.get('file')}: {item.get('count')} total "
                f"({item.get('critical', 0)} critical, {item.get('high', 0)} high)"
            )
        write_line("Top OWASP Categories", font="Helvetica-Bold", size=11)
        for item in owasp_categories[:15]:
            write_line(f"- {item.get('owasp_category')}: {item.get('count')}")
        write_line("Affected Modules", font="Helvetica-Bold", size=11)
        for item in affected_modules[:20]:
            write_line(
                f"- {item.get('module')}: {item.get('count')} total "
                f"({item.get('critical', 0)} critical, {item.get('high', 0)} high)"
            )
        write_line("Action Plan", font="Helvetica-Bold", size=11)
        for step in action_plan[:10]:
            write_line(f"- {step}")
        write_quality_benchmark_section()
        write_line("Alert Details", font="Helvetica-Bold", size=11)
        for alert in alerts[:35]:
            write_line(f"[{alert.get('severity')}] {alert.get('title')} ({alert.get('count')})", font="Helvetica-Bold", size=9)
            write_line(f"CWE: {alert.get('cwe')} | OWASP: {alert.get('owasp')}", size=8)
            lead = alert.get("findings", [{}])[0]
            write_line(f"Tool: {_display_report_tool_name(lead.get('tool', 'CodeSentinelX'))}", size=8)
            write_line(f"Description:", size=8)
            write_block(str(lead.get("description", "N/A")), size=8)
            write_line(f"Impact: {str(lead.get('business_impact', ''))}", size=8)
            write_line("Recommendation:", size=8)
            write_block(str(lead.get("recommendation", "N/A")), size=8)
            write_line("Instances:", size=8)
            for finding in alert.get("findings", [])[:8]:
                location = f"{_normalize_path(str(finding.get('file_path', 'unknown')))}:{finding.get('line_number', 1)}"
                write_line(
                    f" - {location} | {finding.get('status', 'Open')} | {_display_report_tool_name(finding.get('tool', 'CodeSentinelX'))}",
                    size=8,
                )
            write_line("", gap=4)
        pdf.save()
        return output_path

    def export_sarif(self, report: dict, output_path: Path) -> Path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        findings = _vulnerability_findings(report)

        rules: dict[str, dict] = {}
        results: list[dict] = []
        severity_map = {
            "Critical": "error",
            "High": "error",
            "Medium": "warning",
            "Low": "note",
            "Info": "note",
        }

        for finding in findings:
            rule_id = str(finding.get("rule_id", "USS-RULE"))
            if rule_id not in rules:
                rules[rule_id] = {
                    "id": rule_id,
                    "shortDescription": {"text": finding.get("vulnerability_title", finding.get("vulnerability_type", "Issue"))},
                    "fullDescription": {"text": finding.get("description", "")},
                    "help": {"text": finding.get("recommendation", "")},
                    "properties": {
                        "tags": [
                            finding.get("owasp_mapping", finding.get("owasp_category", "")),
                            finding.get("cwe_id") or finding.get("cwe") or "",
                        ],
                    },
                }

            results.append(
                {
                    "ruleId": rule_id,
                    "level": severity_map.get(str(finding.get("severity", "Medium")), "warning"),
                    "message": {"text": finding.get("business_impact", finding.get("description", ""))},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": _normalize_path(str(finding.get("file_path", "unknown")))},
                                "region": {"startLine": max(1, int(finding.get("line_number", 1)))},
                            }
                        }
                    ],
                }
            )

        sarif = {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": report.get("scanner", {}).get("name", "CodeSentinelX"),
                            "version": report.get("scanner", {}).get("version", "1.0.0"),
                            "rules": list(rules.values()),
                        }
                    },
                    "results": results,
                }
            ],
        }
        output_path.write_text(json.dumps(sarif, indent=2), encoding="utf-8")
        return output_path

    def export(self, report: dict, fmt: str, output_path: Path | None = None, report_type: str = "combined") -> Path:
        export_root = self._ensure_export_dir()
        normalized_fmt = fmt.lower()
        normalized_report = report_type.lower()
        if normalized_report not in {"combined", "existing", "vulnerability", "fixes"}:
            raise ValueError(f"Unsupported report type: {report_type}")

        if output_path is None:
            timestamp_source = (
                report.get("vulnerability_fixed_code_report", {}).get("generated_at")
                or report.get("existing_implementation_report", {}).get("generated_at")
                or report.get("executive_summary", {}).get("generated_at")
                or ""
            )
            date_part, time_part = _extract_export_date_time(str(timestamp_source))
            target_token = _extract_export_target_name(report)
            extension = "sairf" if normalized_fmt == "sarif" else normalized_fmt
            output_path = export_root / f"{date_part}_{time_part}_{normalized_report}_{target_token}.{extension}"

        if normalized_fmt == "json":
            return self.export_json(report, output_path, report_type=normalized_report)
        if normalized_fmt == "html":
            return self.export_html(report, output_path, report_type=normalized_report)
        if normalized_fmt == "pdf":
            return self.export_pdf(report, output_path, report_type=normalized_report)
        if normalized_fmt == "sarif":
            if normalized_report in {"existing", "fixes"}:
                raise ValueError("SARIF export is only available for vulnerability report or combined report.")
            return self.export_sarif(report, output_path)

        raise ValueError(f"Unsupported export format: {fmt}")

    def _render_html(self, report: dict, report_type: str = "combined") -> str:
        normalized = report_type.lower()
        if normalized == "existing":
            return self._render_existing_html(report)
        if normalized == "vulnerability":
            return self._render_vulnerability_html(report)
        if normalized == "fixes":
            return self._render_fixes_html(report)
        return self._render_combined_html(report)

    def _render_existing_html(self, report: dict) -> str:
        existing = report.get("existing_implementation_report", {})
        summary = existing.get("summary", {})
        controls = existing.get("controls", [])
        matrix = existing.get("compliance_matrix", [])
        benchmark_section = _render_quality_benchmark_html_section(report)

        summary_rows = "".join(
            f"<tr><td>{html.escape(str(key).replace('_', ' ').title())}</td><td>{html.escape(str(value))}</td></tr>"
            for key, value in summary.items()
        )

        control_rows = "".join(
            (
                "<tr>"
                f"<td>{html.escape(str(control.get('name', 'Control')))}</td>"
                f"<td>{html.escape(str(control.get('category', 'Security')))}</td>"
                f"<td>{html.escape(str(control.get('coverage_level', 'N/A')))}</td>"
                f"<td>{html.escape(', '.join(control.get('standard_mappings', [])[:5]))}</td>"
                "</tr>"
            )
            for control in controls
        )

        matrix_rows = "".join(
            (
                "<tr>"
                f"<td>{html.escape(str(item.get('standard', 'N/A')))}</td>"
                f"<td>{item.get('control_count', 0)}</td>"
                f"<td>{html.escape(str(item.get('status', 'partial')))}</td>"
                "</tr>"
            )
            for item in matrix
        )

        return f"""
<!doctype html>
<html lang='en'>
<head>
  <meta charset='utf-8'>
  <meta name='viewport' content='width=device-width,initial-scale=1'>
  <title>CodeSentinelX Existing Security Report</title>
  <style>
    body {{ font-family: "Segoe UI Variable Text", "Segoe UI", "Trebuchet MS", Arial, Helvetica, sans-serif; font-size: 13.5px; line-height: 1.58; letter-spacing: .01em; background:radial-gradient(circle at 20% -20%, #1c3a60, #071321 45%); margin:0; padding:18px; color:#dce9f7; }}
    h1 {{ font-size: 34px; line-height: 1.06; letter-spacing: -.03em; margin: 10px 0 6px; }}
    h2 {{ font-size: 22px; line-height: 1.14; letter-spacing: -.02em; margin: 20px 0 12px; }}
    table {{ width:100%; border-collapse: collapse; line-height: 1.52; }}
    th,td {{ border:1px solid #294a6c; padding:10px 12px; text-align:left; vertical-align:top; }}
    th {{ background:rgba(16,37,63,.32); color:#c6d9ec; }}
    td {{ background:rgba(11,26,45,.14); }}
    .meta {{ margin:5px 0; color:#95afc8; font-size:12.5px; }}
    table {{ border-radius:16px; overflow:hidden; }}
    {_report_globe_css()}
  </style>
</head>
<body>
  <h1>CodeSentinelX Existing Security Implementation Report</h1>
  <p class='meta'><strong>Target:</strong> {html.escape(str(existing.get('target_path', 'N/A')))}</p>
    <p class='meta'><strong>Generated:</strong> {html.escape(_format_display_timestamp(str(existing.get('generated_at', 'N/A'))))}</p>
  <h2>Coverage Summary</h2>
  <table>
    <thead><tr><th>Metric</th><th>Value</th></tr></thead>
    <tbody>{summary_rows or "<tr><td colspan='2'>No summary data</td></tr>"}</tbody>
  </table>
  <h2>Implemented Controls</h2>
  <table>
    <thead><tr><th>Control</th><th>Category</th><th>Coverage</th><th>Standards</th></tr></thead>
    <tbody>{control_rows or "<tr><td colspan='4'>No controls detected.</td></tr>"}</tbody>
  </table>
  <h2>Compliance Matrix</h2>
  <table>
    <thead><tr><th>Standard</th><th>Control Count</th><th>Status</th></tr></thead>
    <tbody>{matrix_rows or "<tr><td colspan='3'>No compliance mapping data.</td></tr>"}</tbody>
  </table>
  {benchmark_section}
</body>
</html>
"""

    def _render_vulnerability_html(self, report: dict) -> str:
        vuln_report = report.get("vulnerability_fixed_code_report", {})
        summary = vuln_report.get("summary", {})
        exec_summary = report.get("executive_summary", {})
        target_path = str(vuln_report.get("target_path", exec_summary.get("target_path", "N/A")))
        generated_at = str(vuln_report.get("generated_at", exec_summary.get("generated_at", "N/A")))
        risk_score = summary.get("risk_score", exec_summary.get("risk_score", 0))
        risk_rating = str(summary.get("risk_rating", exec_summary.get("risk_rating", "N/A")))
        findings = _sorted_findings(report)
        alerts = _alert_groups(findings)
        affected_files = _affected_files(findings)
        affected_folders = _affected_folders(findings)
        affected_modules = summary.get("affected_modules", exec_summary.get("affected_modules", []))
        owasp_rows = _owasp_counts(findings)
        action_plan = exec_summary.get("recommended_action_plan", [])
        benchmark_section = _render_quality_benchmark_html_section(report)

        summary_rows = "".join(
            (
                f"<tr><td class='risk-{severity.lower()}'>{severity}</td>"
                f"<td align='center'>{summary.get('severity_distribution', {}).get(severity, 0)}</td></tr>"
            )
            for severity in ["Critical", "High", "Medium", "Low", "Info"]
        )

        alert_rows = "".join(
            (
                "<tr>"
                f"<td class='risk-{html.escape(str(alert.get('severity', 'Info')).lower())}'>{html.escape(str(alert.get('severity', 'Info')))}</td>"
                f"<td><button type='button' class='alert-link' data-alert-id='{html.escape(str(alert.get('id')))}' "
                f"aria-controls='{html.escape(str(alert.get('id')))}' aria-expanded='false'>{html.escape(str(alert.get('title')))}</button></td>"
                f"<td align='center'>{alert.get('count', 0)}</td>"
                f"<td>{html.escape(str(alert.get('cwe', 'N/A')))}</td>"
                f"<td>{html.escape(str(alert.get('owasp', 'N/A')))}</td>"
                "</tr>"
            )
            for alert in alerts
        )

        owasp_table_rows = "".join(
            (
                "<tr>"
                f"<td>{html.escape(str(item.get('owasp_category', 'N/A')))}</td>"
                f"<td align='center'>{item.get('count', 0)}</td>"
                "</tr>"
            )
            for item in owasp_rows
        )

        module_rows = "".join(
            (
                "<tr>"
                f"<td>{html.escape(str(item.get('module', 'root')))}</td>"
                f"<td align='center'>{item.get('count', 0)}</td>"
                f"<td align='center'>{item.get('critical', 0)}</td>"
                f"<td align='center'>{item.get('high', 0)}</td>"
                "</tr>"
            )
            for item in affected_modules
        )

        file_rows = "".join(
            (
                "<tr>"
                f"<td>{html.escape(str(item.get('file', 'unknown')))}</td>"
                f"<td>{html.escape(str(item.get('folder', '.')))}</td>"
                f"<td align='center'>{item.get('critical', 0)}</td>"
                f"<td align='center'>{item.get('high', 0)}</td>"
                f"<td align='center'>{item.get('medium', 0)}</td>"
                f"<td align='center'>{item.get('low', 0)}</td>"
                f"<td align='center'>{item.get('info', 0)}</td>"
                f"<td align='center'>{item.get('count', 0)}</td>"
                "</tr>"
            )
            for item in affected_files
        )

        folder_rows = "".join(
            (
                "<tr>"
                f"<td>{html.escape(str(item.get('folder', '.')))}</td>"
                f"<td align='center'>{item.get('critical', 0)}</td>"
                f"<td align='center'>{item.get('high', 0)}</td>"
                f"<td align='center'>{item.get('medium', 0)}</td>"
                f"<td align='center'>{item.get('low', 0)}</td>"
                f"<td align='center'>{item.get('info', 0)}</td>"
                f"<td align='center'>{item.get('count', 0)}</td>"
                "</tr>"
            )
            for item in affected_folders
        )

        detail_sections = "".join(
            self._render_alert_detail(alert) for alert in alerts
        )

        action_rows = "".join(f"<li>{html.escape(str(item))}</li>" for item in action_plan)

        return f"""
<!doctype html>
<html lang='en'>
<head>
  <meta charset='utf-8'>
  <meta name='viewport' content='width=device-width,initial-scale=1'>
  <title>CodeSentinelX Vulnerability Report (ZAP-Style)</title>
  <style>
    body {{ font-family: "Segoe UI Variable Text", "Segoe UI", "Trebuchet MS", Arial, Helvetica, sans-serif; font-size: 13.5px; line-height: 1.58; letter-spacing: .01em; background:radial-gradient(circle at 20% -20%, #1c3a60, #071321 45%); margin:0; padding:18px; color:#dce9f7; }}
    h1 {{ text-align:center; font-size:35px; line-height:1.05; letter-spacing:-.03em; margin:10px 0; }}
    h2 {{ font-size:23px; line-height:1.14; letter-spacing:-.02em; margin:22px 0 12px; }}
    h3 {{ font-size:17px; line-height:1.22; margin:16px 0 8px; }}
    h4 {{ font-size:14px; line-height:1.32; margin:12px 0 8px; }}
    table {{ width:100%; border-collapse:collapse; margin-bottom:14px; line-height:1.52; }}
    th, td {{ border:1px solid #c1c8ce; padding:10px 12px; vertical-align:top; }}
    th {{ background:rgba(16,37,63,.32); color:#c6d9ec; text-align:left; cursor:pointer; }}
    td {{ background:rgba(11,26,45,.14); border-color:#294a6c; }}
    .meta {{ margin:4px 0; color:#95afc8; font-size:12.5px; }}
    .summary {{ max-width:460px; }}
    .risk-critical {{ background:#b91c1c; color:#fff; font-weight:bold; }}
    .risk-high {{ background:#ea580c; color:#fff; font-weight:bold; }}
    .risk-medium {{ background:#eab308; color:#111; font-weight:bold; }}
    .risk-low {{ background:#2563eb; color:#fff; font-weight:bold; }}
    .risk-info {{ background:#16a34a; color:#fff; font-weight:bold; }}
    .two-col {{ display:grid; grid-template-columns:1fr 1fr; gap:12px; }}
    .toolbar {{ display:flex; gap:8px; align-items:center; margin:8px 0 12px; flex-wrap:wrap; }}
    .toolbar input {{ background:rgba(7,20,36,.24); border:1px solid #294a6c; border-radius:10px; color:#dce9f7; padding:9px 12px; min-width:240px; }}
    .alert-block {{ margin-top:16px; padding-top:8px; border-top:2px solid #355376; }}
    .hidden-section {{ display:none; }}
    .alert-link {{ background:none; border:none; color:#35c7ff; text-decoration:underline; cursor:pointer; font:inherit; padding:0; }}
    .code {{ font-family:Consolas, monospace; white-space:pre-wrap; background:rgba(7,19,33,.16); border:1px solid rgba(120,168,205,.24); border-radius:14px; padding:12px; color:#dce9f7; line-height:1.55; }}
    .chart-wrap {{ display:grid; grid-template-columns:320px 1fr; gap:12px; align-items:center; }}
    .legend-item {{ display:flex; gap:8px; align-items:center; margin:4px 0; color:#95afc8; }}
    .dot {{ width:10px; height:10px; border-radius:50%; }}
    .bars {{ display:grid; gap:8px; }}
    .bar-row {{ display:grid; grid-template-columns:220px 1fr auto; gap:10px; align-items:center; }}
    .bar-track {{ height:12px; border:1px solid #294a6c; border-radius:999px; overflow:hidden; background:#071424; }}
    .bar-fill {{ height:100%; background:linear-gradient(90deg,#1f88ff,#35c7ff); }}
    .bar-label {{ color:#95afc8; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }}
    @media (max-width: 980px) {{ .two-col {{ grid-template-columns:1fr; }} }}
    {_report_globe_css()}
  </style>
</head>
<body>
  <h1>CodeSentinelX Vulnerability Report (ZAP-Style)</h1>
  <p class='meta'><strong>Target:</strong> {html.escape(target_path)}</p>
  <p class='meta'><strong>Generated:</strong> {html.escape(_format_display_timestamp(generated_at))}</p>
  <p class='meta'><strong>Risk Score:</strong> {risk_score} ({html.escape(risk_rating)})</p>

  <h2>Summary of Alerts</h2>
  <div class='two-col'>
    <div>
      <table id='severitySummary' class='summary'>
        <thead><tr><th data-sort-index='0' data-sort-type='text'>Risk Level</th><th data-sort-index='1' data-sort-type='number' align='center'>Number of Alerts</th></tr></thead>
        <tbody>{summary_rows}</tbody>
      </table>
    </div>
    <div class='chart-wrap'>
      <canvas id='severityChart' width='280' height='280'></canvas>
      <div id='severityLegend'></div>
    </div>
  </div>

  <div class='two-col'>
    <div>
      <h2>Alerts by Type</h2>
      <table id='alertTable'>
        <thead><tr><th data-sort-index='0' data-sort-type='text'>Risk</th><th data-sort-index='1' data-sort-type='text'>Alert</th><th data-sort-index='2' data-sort-type='number' align='center'>Instances</th><th data-sort-index='3' data-sort-type='text'>CWE</th><th data-sort-index='4' data-sort-type='text'>OWASP</th></tr></thead>
        <tbody>{alert_rows or "<tr><td colspan='5'>No findings.</td></tr>"}</tbody>
      </table>
    </div>
    <div>
      <h2>OWASP Category Counts</h2>
      <div class='toolbar'><input id='owaspSearch' type='search' placeholder='Search OWASP category'></div>
      <table id='owaspTable'>
        <thead><tr><th data-sort-index='0' data-sort-type='text'>OWASP Category</th><th data-sort-index='1' data-sort-type='number' align='center'>Count</th></tr></thead>
        <tbody>{owasp_table_rows or "<tr><td colspan='2'>No OWASP data.</td></tr>"}</tbody>
      </table>
      <div id='owaspBars' class='bars'></div>
    </div>
  </div>

  <h2>Affected Modules</h2>
  <div class='toolbar'><input id='moduleSearch' type='search' placeholder='Search module'></div>
  <table id='moduleTable'>
    <thead><tr><th data-sort-index='0' data-sort-type='text'>Module</th><th data-sort-index='1' data-sort-type='number'>Total</th><th data-sort-index='2' data-sort-type='number'>Critical</th><th data-sort-index='3' data-sort-type='number'>High</th></tr></thead>
    <tbody>{module_rows or "<tr><td colspan='4'>No affected modules.</td></tr>"}</tbody>
  </table>

  <h2>Affected Files and Folders</h2>
  <div class='toolbar'><input id='fileSearch' type='search' placeholder='Search file or folder'></div>
  <table id='fileTable'>
    <thead><tr><th data-sort-index='0' data-sort-type='text'>File</th><th data-sort-index='1' data-sort-type='text'>Folder</th><th data-sort-index='2' data-sort-type='number'>Critical</th><th data-sort-index='3' data-sort-type='number'>High</th><th data-sort-index='4' data-sort-type='number'>Medium</th><th data-sort-index='5' data-sort-type='number'>Low</th><th data-sort-index='6' data-sort-type='number'>Info</th><th data-sort-index='7' data-sort-type='number'>Total</th></tr></thead>
    <tbody>{file_rows or "<tr><td colspan='8'>No affected files.</td></tr>"}</tbody>
  </table>

  <h2>Affected Folders Summary</h2>
  <table>
    <thead><tr><th>Folder</th><th>Critical</th><th>High</th><th>Medium</th><th>Low</th><th>Info</th><th>Total</th></tr></thead>
    <tbody>{folder_rows or "<tr><td colspan='7'>No affected folders.</td></tr>"}</tbody>
  </table>

  <h2>Action Plan</h2>
  <ol>{action_rows or "<li>No action plan available.</li>"}</ol>

  {benchmark_section}
  <h2>Detailed Findings</h2>
  {detail_sections or "<p>No findings available.</p>"}
  <script>
    (function () {{
      var severityColors = {{ Critical: "#ff5b77", High: "#ff9b4b", Medium: "#ffd65e", Low: "#67b8ff", Info: "#70d5ab" }};

      function sortTable(table, index, type, asc) {{
        var tbody = table.querySelector("tbody");
        if (!tbody) return;
        var rows = Array.from(tbody.querySelectorAll("tr"));
        rows.sort(function (a, b) {{
          var av = (a.children[index] && a.children[index].textContent ? a.children[index].textContent : "").trim();
          var bv = (b.children[index] && b.children[index].textContent ? b.children[index].textContent : "").trim();
          if (type === "number") {{
            var an = Number(av || 0);
            var bn = Number(bv || 0);
            return asc ? an - bn : bn - an;
          }}
          av = av.toLowerCase();
          bv = bv.toLowerCase();
          if (av < bv) return asc ? -1 : 1;
          if (av > bv) return asc ? 1 : -1;
          return 0;
        }});
        rows.forEach(function (row) {{ tbody.appendChild(row); }});
      }}

      function initTable(tableId, searchId) {{
        var table = document.getElementById(tableId);
        if (!table) return;
        var headers = table.querySelectorAll("th[data-sort-index]");
        headers.forEach(function (header) {{
          header.addEventListener("click", function () {{
            var index = Number(header.getAttribute("data-sort-index") || 0);
            var type = header.getAttribute("data-sort-type") || "text";
            var asc = header.getAttribute("data-dir") !== "asc";
            header.setAttribute("data-dir", asc ? "asc" : "desc");
            sortTable(table, index, type, asc);
          }});
        }});
        if (!searchId) return;
        var input = document.getElementById(searchId);
        if (!input) return;
        input.addEventListener("input", function () {{
          var query = (input.value || "").toLowerCase();
          var tbody = table.querySelector("tbody");
          if (!tbody) return;
          Array.from(tbody.querySelectorAll("tr")).forEach(function (row) {{
            var text = (row.textContent || "").toLowerCase();
            row.style.display = !query || text.indexOf(query) >= 0 ? "" : "none";
          }});
        }});
      }}

      function drawSeverityChart() {{
        var canvas = document.getElementById("severityChart");
        if (!canvas || !canvas.getContext) return;
        var summaryRows = Array.from(document.querySelectorAll("#severitySummary tbody tr"));
        var labels = [];
        var counts = [];
        summaryRows.forEach(function (row) {{
          var cells = row.children;
          if (cells.length >= 2) {{
            labels.push((cells[0].textContent || "").trim());
            counts.push(Number((cells[1].textContent || "0").trim()));
          }}
        }});
        var total = counts.reduce(function (sum, value) {{ return sum + value; }}, 0);
        var ctx = canvas.getContext("2d");
        if (!ctx || total <= 0) return;
        var cx = canvas.width / 2;
        var cy = canvas.height / 2;
        var outer = Math.min(cx, cy) - 8;
        var inner = outer * 0.58;
        var start = -Math.PI / 2;
        labels.forEach(function (label, idx) {{
          var value = counts[idx];
          if (value <= 0) return;
          var arc = (value / total) * Math.PI * 2;
          ctx.beginPath();
          ctx.moveTo(cx, cy);
          ctx.arc(cx, cy, outer, start, start + arc);
          ctx.closePath();
          ctx.fillStyle = severityColors[label] || "#70d5ab";
          ctx.fill();
          start += arc;
        }});
        ctx.beginPath();
        ctx.arc(cx, cy, inner, 0, Math.PI * 2);
        ctx.fillStyle = "#0b1a2d";
        ctx.fill();
        ctx.fillStyle = "#dce9f7";
        ctx.font = "700 26px Segoe UI";
        ctx.textAlign = "center";
        ctx.fillText(String(total), cx, cy + 8);
        ctx.textAlign = "left";
        var legend = document.getElementById("severityLegend");
        if (legend) {{
          legend.innerHTML = labels.map(function (label, idx) {{
            return "<div class='legend-item'><span class='dot' style='background:" + (severityColors[label] || "#70d5ab") + "'></span><span>" + label + ": " + counts[idx] + "</span></div>";
          }}).join("");
        }}
      }}

      function drawOwaspBars() {{
        var rows = Array.from(document.querySelectorAll("#owaspTable tbody tr")).map(function (row) {{
          var cells = row.children;
          return {{ label: cells[0] ? (cells[0].textContent || "").trim() : "", count: Number(cells[1] ? (cells[1].textContent || "0").trim() : "0") }};
        }}).filter(function (item) {{ return item.label; }});
        var root = document.getElementById("owaspBars");
        if (!root) return;
        if (!rows.length) {{
          root.innerHTML = "<p>No OWASP data available.</p>";
          return;
        }}
        var max = rows.reduce(function (current, item) {{ return Math.max(current, item.count); }}, 1);
        root.innerHTML = rows.slice(0, 10).map(function (item) {{
          var width = Math.max(2, Math.round((item.count / max) * 100));
          return "<div class='bar-row'><div class='bar-label' title='" + item.label + "'>" + item.label + "</div><div class='bar-track'><div class='bar-fill' style='width:" + width + "%'></div></div><div>" + item.count + "</div></div>";
        }}).join("");
      }}

      function openAlertSection(id) {{
        var target = document.getElementById(id);
        if (!target) return;
        document.querySelectorAll(".alert-block").forEach(function (section) {{
          if (section.id === id) {{
            section.classList.remove("hidden-section");
          }} else {{
            section.classList.add("hidden-section");
          }}
        }});
        document.querySelectorAll(".alert-link").forEach(function (item) {{
          item.setAttribute("aria-expanded", item.getAttribute("data-alert-id") === id ? "true" : "false");
        }});
        target.scrollIntoView({{ behavior: "smooth", block: "start" }});
        if (!target.hasAttribute("tabindex")) {{
          target.setAttribute("tabindex", "-1");
        }}
      }}

      document.querySelectorAll(".alert-link").forEach(function (button) {{
        button.addEventListener("click", function () {{
          var id = button.getAttribute("data-alert-id");
          if (!id) return;
          openAlertSection(id);
        }});
      }});

      initTable("severitySummary");
      initTable("alertTable");
      initTable("owaspTable", "owaspSearch");
      initTable("moduleTable", "moduleSearch");
      initTable("fileTable", "fileSearch");
      drawSeverityChart();
      drawOwaspBars();
    }})();
  </script>
</body>
</html>
"""

    def _render_alert_detail(self, alert: dict) -> str:
        findings = alert.get("findings", [])
        lead = findings[0] if findings else {}

        instance_rows = "".join(
            (
                "<tr>"
                f"<td>{html.escape(_normalize_path(str(item.get('file_path', 'unknown'))))}</td>"
                f"<td>{html.escape(_folder_name(str(item.get('file_path', 'unknown'))))}</td>"
                f"<td align='center'>{int(item.get('line_number', 1))}</td>"
                f"<td>{html.escape(str(item.get('severity', 'Info')))}</td>"
                f"<td>{html.escape(str(item.get('status', 'Open')))}</td>"
                f"<td>{html.escape(_display_report_tool_name(item.get('tool', 'CodeSentinelX')))}</td>"
                f"<td>{html.escape(str(item.get('cwe_id') or item.get('cwe') or 'N/A'))}</td>"
                f"<td>{html.escape(str(item.get('owasp_mapping') or item.get('owasp_category') or 'N/A'))}</td>"
                "</tr>"
            )
            for item in findings
        )

        return (
            f"<section id='{html.escape(str(alert.get('id', 'alert')))}' class='alert-block hidden-section'>"
            f"<h3>[{html.escape(str(alert.get('severity', 'Info')))}] {html.escape(str(alert.get('title', 'Issue')))} ({alert.get('count', 0)})</h3>"
            "<table>"
            f"<tr><th width='20%'>CWE</th><td>{html.escape(str(alert.get('cwe', 'N/A')))}</td></tr>"
            f"<tr><th>OWASP</th><td>{html.escape(str(alert.get('owasp', 'N/A')))}</td></tr>"
            f"<tr><th>Description</th><td>{html.escape(str(lead.get('description', 'N/A')))}</td></tr>"
            f"<tr><th>Business Impact</th><td>{html.escape(str(lead.get('business_impact', 'N/A')))}</td></tr>"
            f"<tr><th>Recommendation</th><td>{html.escape(str(lead.get('recommendation', 'N/A')))}</td></tr>"
            + (
                f"<tr><th>Dependency Authenticity</th><td>{html.escape(_dependency_auth_summary(lead))}<br><span class='muted'>{html.escape(_dependency_auth_detail(lead))}</span></td></tr>"
                if _dependency_auth_summary(lead)
                else ""
            )
            + f"<tr><th>Source Tool</th><td>{html.escape(_display_report_tool_name(lead.get('tool', 'CodeSentinelX')))}</td></tr>"
            + "</table>"
            "<h4>Instances</h4>"
            "<table>"
            "<thead><tr><th>File Path</th><th>Folder</th><th>Line</th><th>Severity</th><th>Status</th><th>Tool</th><th>CWE</th><th>OWASP</th></tr></thead>"
            f"<tbody>{instance_rows}</tbody>"
            "</table>"
            "</section>"
        )

    def _render_fixes_html(self, report: dict) -> str:
        vuln_report = report.get("vulnerability_fixed_code_report", {})
        summary = vuln_report.get("summary", {})
        findings = _sorted_findings(report)
        target_path = str(vuln_report.get("target_path", report.get("executive_summary", {}).get("target_path", "N/A")))
        generated_at = str(vuln_report.get("generated_at", report.get("executive_summary", {}).get("generated_at", "N/A")))
        benchmark_section = _render_quality_benchmark_html_section(report)

        severity_rows = "".join(
            (
                "<tr>"
                f"<td>{severity}</td>"
                f"<td align='center'>{summary.get('severity_distribution', {}).get(severity, 0)}</td>"
                "</tr>"
            )
            for severity in ["Critical", "High", "Medium", "Low", "Info"]
        )

        verification_summary = _fix_verification_summary(findings)
        verification_rows = "".join(
            f"<tr><td>{html.escape(label)}</td><td align='center'>{value}</td></tr>"
            for label, value in [
                ("Performed", verification_summary["performed"]),
                ("Verified Fixed", verification_summary["verified_fixed"]),
                ("Verification Failed", verification_summary["verification_failed"]),
                ("Inconclusive", verification_summary["inconclusive"]),
                ("Workspace Build Passed", verification_summary["build_verified"]),
                ("Workspace Build Failed", verification_summary["build_failed"]),
                ("Workspace Tests Passed", verification_summary["test_verified"]),
                ("Workspace Tests Failed", verification_summary["test_failed"]),
                ("Not Applicable", verification_summary["not_applicable"]),
                ("Skipped", verification_summary["skipped"]),
            ]
        )

        queue_rows = "".join(
            (
                "<tr>"
                f"<td>{idx + 1}</td>"
                f"<td>{html.escape(str(item.get('severity', 'Info')))}</td>"
                f"<td>{html.escape(str(item.get('vulnerability_title') or item.get('vulnerability_type') or 'Issue'))}</td>"
                f"<td>{html.escape(_normalize_path(str(item.get('file_path', 'unknown'))))}</td>"
                f"<td align='center'>{int(item.get('line_number', 1))}</td>"
                f"<td>{html.escape(str(item.get('cwe_id') or item.get('cwe') or 'N/A'))}</td>"
                f"<td>{html.escape(str(item.get('owasp_mapping') or item.get('owasp_category') or 'N/A'))}</td>"
                "</tr>"
            )
            for idx, item in enumerate(findings)
        )

        detail_sections = "".join(
            (
                "<section class='fix-card'>"
                f"<h3>[{html.escape(str(item.get('severity', 'Info')))}] {html.escape(str(item.get('vulnerability_title') or item.get('vulnerability_type') or 'Issue'))}</h3>"
                f"<p><strong>Location:</strong> {html.escape(_normalize_path(str(item.get('file_path', 'unknown'))))}:{int(item.get('line_number', 1))}</p>"
                f"<p><strong>CWE:</strong> {html.escape(str(item.get('cwe_id') or item.get('cwe') or 'N/A'))} | "
                f"<strong>OWASP:</strong> {html.escape(str(item.get('owasp_mapping') or item.get('owasp_category') or 'N/A'))}</p>"
                f"<p><strong>Recommendation:</strong> {html.escape(str(item.get('recommendation', 'N/A')))}</p>"
                + (
                    f"<p><strong>Dependency Authenticity:</strong> {html.escape(_dependency_auth_summary(item))}<br><span class='meta'>{html.escape(_dependency_auth_detail(item))}</span></p>"
                    if _dependency_auth_summary(item)
                    else ""
                )
                + (
                    f"<p><strong>Fix Verification:</strong> {html.escape(str((item.get('fix_verification') or {}).get('result', 'not_applicable')))} | {html.escape(str((item.get('fix_verification') or {}).get('reason', '')))}</p>"
                    if item.get("fix_verification")
                    else ""
                )
                + (
                    f"<p><strong>Workspace Build:</strong> {html.escape(str(((item.get('fix_verification') or {}).get('build_verification') or {}).get('status', 'unknown')))} | <code>{html.escape(str(((item.get('fix_verification') or {}).get('build_verification') or {}).get('command', '')))}</code></p><pre>{html.escape(str(((item.get('fix_verification') or {}).get('build_verification') or {}).get('output', '')))}</pre>"
                    if (item.get("fix_verification") or {}).get("build_verification")
                    else ""
                )
                + (
                    f"<p><strong>Workspace Test:</strong> {html.escape(str(((item.get('fix_verification') or {}).get('test_verification') or {}).get('status', 'unknown')))} | <code>{html.escape(str(((item.get('fix_verification') or {}).get('test_verification') or {}).get('command', '')))}</code></p><pre>{html.escape(str(((item.get('fix_verification') or {}).get('test_verification') or {}).get('output', '')))}</pre>"
                    if (item.get("fix_verification") or {}).get("test_verification")
                    else ""
                )
                + "<div class='code-grid'>"
                "<div><h4>Original Code</h4>"
                f"<pre>{html.escape(str(item.get('original_code', 'Snippet unavailable.')))}</pre></div>"
                "<div><h4>Suggested Fix</h4>"
                f"<pre>{html.escape(str(item.get('ai_suggested_fix') or item.get('fixed_code', 'No direct fix available.')))}</pre></div>"
                "</div>"
                f"<h4>Patch Preview</h4><pre>{html.escape(str(item.get('patch_preview', 'No patch preview available.')))}</pre>"
                "</section>"
            )
            for item in findings[:220]
        )

        truncated_note = (
            f"<p>{len(findings) - 220} additional finding(s) hidden for readability.</p>"
            if len(findings) > 220
            else ""
        )

        return f"""
<!doctype html>
<html lang='en'>
<head>
  <meta charset='utf-8'>
  <meta name='viewport' content='width=device-width,initial-scale=1'>
  <title>CodeSentinelX Original and Suggested Fix Report</title>
  <style>
    body {{ font-family: "Segoe UI Variable Text", "Segoe UI", "Trebuchet MS", Arial, Helvetica, sans-serif; font-size: 13.5px; line-height: 1.58; letter-spacing: .01em; background:radial-gradient(circle at 20% -20%, #1c3a60, #071321 45%); margin:0; padding:18px; color:#dce9f7; }}
    h1 {{ font-size:35px; line-height:1.05; letter-spacing:-.03em; margin:10px 0; }}
    h2 {{ font-size:23px; line-height:1.14; letter-spacing:-.02em; margin:22px 0 12px; }}
    h3 {{ font-size:17px; line-height:1.22; margin:16px 0 8px; }}
    h4 {{ font-size:14px; line-height:1.32; margin:12px 0 8px; }}
    table {{ width:100%; border-collapse:collapse; margin-bottom:14px; line-height:1.52; }}
    th, td {{ border:1px solid #294a6c; padding:10px 12px; vertical-align:top; }}
    th {{ background:rgba(16,37,63,.6); color:#c6d9ec; text-align:left; }}
    td {{ background:rgba(11,26,45,.34); }}
    .meta {{ margin:4px 0; color:#95afc8; font-size:12.5px; }}
    .panel {{ margin-bottom:14px; }}
    .summary {{ max-width:460px; }}
    .fix-card {{ margin-top:14px; padding:14px; border:1px solid rgba(120,168,205,.28); border-radius:14px; background:rgba(11,26,45,.14); }}
    .code-grid {{ display:grid; grid-template-columns:1fr 1fr; gap:14px; }}
    pre {{ margin:0; white-space:pre-wrap; word-break:break-word; font-family:Consolas, monospace; background:rgba(7,19,33,.16); border:1px solid rgba(120,168,205,.24); border-radius:14px; padding:12px; color:#dce9f7; line-height:1.55; }}
    @media (max-width: 980px) {{ .code-grid {{ grid-template-columns:1fr; }} }}
    {_report_globe_css()}
  </style>
</head>
<body>
  <section class='panel'>
    <h1>CodeSentinelX Original and Suggested Fix Report</h1>
    <p class='meta'><strong>Target:</strong> {html.escape(target_path)}</p>
    <p class='meta'><strong>Generated:</strong> {html.escape(_format_display_timestamp(generated_at))}</p>
    <p class='meta'><strong>Total Findings:</strong> {summary.get('total_findings', len(findings))}</p>
  </section>
  <section class='panel'>
    <h2>Severity Summary</h2>
    <table class='summary'>
      <thead><tr><th>Severity</th><th>Count</th></tr></thead>
      <tbody>{severity_rows}</tbody>
    </table>
  </section>
  <section class='panel'>
    <h2>Fix Verification Summary</h2>
    <table class='summary'>
      <thead><tr><th>Metric</th><th>Count</th></tr></thead>
      <tbody>{verification_rows}</tbody>
    </table>
  </section>
  {benchmark_section}
  <section class='panel'>
    <h2>Fix Queue</h2>
    <table>
      <thead><tr><th>#</th><th>Severity</th><th>Issue</th><th>File</th><th>Line</th><th>CWE</th><th>OWASP</th></tr></thead>
      <tbody>{queue_rows or "<tr><td colspan='7'>No findings available.</td></tr>"}</tbody>
    </table>
  </section>
  <section class='panel'>
    <h2>Original and Suggested Fix Details</h2>
    {detail_sections or "<p>No fix details available.</p>"}
    {truncated_note}
  </section>
</body>
</html>
"""

    def _render_combined_html(self, report: dict) -> str:
        exec_summary = report.get("executive_summary", {})
        existing = report.get("existing_implementation_report", {})
        vuln = report.get("vulnerability_fixed_code_report", {})
        summary = vuln.get("summary", {})
        findings = _sorted_findings(report)
        severity_dist = summary.get("severity_distribution", {}) if isinstance(summary.get("severity_distribution"), dict) else {}
        risk_intel = summary.get("risk_intelligence", {}) if isinstance(summary.get("risk_intelligence"), dict) else {}
        known_kev = int(risk_intel.get("known_exploited_findings", 0) or 0)
        severity_rows = "".join(
            f"<tr><td>{severity}</td><td align='center'>{int(severity_dist.get(severity, 0))}</td></tr>"
            for severity in ["Critical", "High", "Medium", "Low", "Info"]
            if int(severity_dist.get(severity, 0)) > 0
        )
        top_rows = "".join(
            (
                "<tr>"
                f"<td>{idx + 1}</td>"
                f"<td>{html.escape(str(item.get('severity', 'Info')))}</td>"
                f"<td>{html.escape(str(item.get('vulnerability_title') or item.get('vulnerability_type') or 'Issue'))}</td>"
                f"<td align='center'>{float(item.get('cvss_score', 0.0)):.1f}</td>"
                f"<td>{html.escape(_normalize_path(str(item.get('file_path', 'unknown'))))}:{int(item.get('line_number', 1))}</td>"
                f"<td>{html.escape(str(item.get('cwe_id') or item.get('cwe') or 'N/A'))}</td>"
                f"<td>{html.escape(str(item.get('owasp_mapping') or item.get('owasp_category') or 'N/A'))}</td>"
                "</tr>"
            )
            for idx, item in enumerate(findings[:30])
        )
        timing_rows_data: list[dict[str, object]] = []
        toolchain_status = vuln.get("toolchain_status", {})
        if isinstance(toolchain_status, dict):
            for tool_name, status in toolchain_status.items():
                if not isinstance(status, dict):
                    continue
                execution = status.get("execution") if isinstance(status.get("execution"), dict) else {}
                timing_rows_data.append(
                    {
                        "tool": str(tool_name),
                        "status": str(execution.get("status") or status.get("message") or "unknown"),
                        "attempted": bool(execution.get("attempted")),
                        "duration_ms": int(execution.get("duration_ms") or 0),
                        "findings_count": int(execution.get("findings_count") or 0),
                        "errors_count": len(execution.get("errors") or []) if isinstance(execution.get("errors"), list) else 0,
                    }
                )
        timing_rows_data.sort(key=lambda item: int(item.get("duration_ms", 0)), reverse=True)
        timing_rows = "".join(
            (
                "<tr>"
                f"<td>{html.escape(str(item.get('tool', '')))}</td>"
                f"<td>{html.escape(str(item.get('status', '')))}</td>"
                f"<td align='center'>{'Yes' if item.get('attempted') else 'No'}</td>"
                f"<td align='right'>{int(item.get('duration_ms', 0))}</td>"
                f"<td align='right'>{int(item.get('findings_count', 0))}</td>"
                f"<td align='right'>{int(item.get('errors_count', 0))}</td>"
                "</tr>"
            )
            for item in timing_rows_data[:40]
        )
        enterprise = summary.get("enterprise_assurance", {}) if isinstance(summary.get("enterprise_assurance"), dict) else {}
        enterprise_rows = "".join(
            row
            for row in [
                f"<tr><td>Status</td><td align='center'>{html.escape(str(enterprise.get('status', '')).upper())}</td></tr>"
                if str(enterprise.get("status", "")).strip()
                else "",
                f"<tr><td>Readiness Score</td><td align='center'>{int(enterprise.get('readiness_score', 0))}</td></tr>"
                if int(enterprise.get("readiness_score", 0) or 0) > 0
                else "",
                f"<tr><td>Required Tools Ready</td><td align='center'>{int(enterprise.get('required_tools_ready', 0))}/{int(enterprise.get('required_tools_total', 0))}</td></tr>"
                if int(enterprise.get("required_tools_total", 0) or 0) > 0
                else "",
                f"<tr><td>Required Coverage</td><td align='center'>{float(enterprise.get('required_tools_coverage_percent', 0.0)):.2f}%</td></tr>"
                if float(enterprise.get("required_tools_coverage_percent", 0.0) or 0) > 0
                else "",
            ]
            if row
        )
        benchmark_section = _render_quality_benchmark_html_section(report)
        return f"""
<!doctype html>
<html lang='en'>
<head>
  <meta charset='utf-8'>
  <meta name='viewport' content='width=device-width,initial-scale=1'>
  <title>CodeSentinelX Combined Report</title>
  <style>
    body {{ margin:0; font-family: "Segoe UI Variable Text", "Segoe UI", "Trebuchet MS", Arial, Helvetica, sans-serif; font-size: 13.5px; line-height: 1.58; letter-spacing: .01em; background:radial-gradient(circle at 20% -20%, #1c3a60, #071321 45%); color:#dce9f7; padding:18px; }}
    main {{ max-width:1260px; margin:0 auto; }}
    .panel {{ background:rgba(11,26,45,.34); border:1px solid #294a6c; border-radius:14px; padding:14px; margin-bottom:14px; }}
    .meta {{ margin:4px 0; color:#95afc8; font-size:12.5px; }}
    .grid {{ display:grid; grid-template-columns:1fr 1fr; gap:14px; }}
    table {{ width:100%; border-collapse:collapse; margin-bottom:12px; line-height:1.52; }}
    th, td {{ border:1px solid #294a6c; padding:10px 12px; vertical-align:top; }}
    th {{ background:rgba(16,37,63,.6); color:#c6d9ec; text-align:left; }}
    td {{ background:rgba(11,26,45,.34); }}
    @media (max-width: 1024px) {{ .grid {{ grid-template-columns:1fr; }} }}
    {_report_globe_css()}
  </style>
</head>
<body>
  <main>
    <section class='panel'>
      <h1>CodeSentinelX Combined Security Report</h1>
      <p class='meta'><strong>Target:</strong> {html.escape(str(exec_summary.get('target_path', 'N/A')))}</p>
      <p class='meta'><strong>Generated:</strong> {html.escape(_format_display_timestamp(str(exec_summary.get('generated_at', 'N/A'))))}</p>
      <p class='meta'><strong>Risk Score:</strong> {float(summary.get('risk_score', exec_summary.get('risk_score', 0)) or 0):.2f} ({html.escape(str(summary.get('risk_rating', exec_summary.get('risk_rating', 'N/A'))) )})</p>
      <p class='meta'><strong>Total Findings:</strong> {int(summary.get('total_findings', len(findings)) or len(findings))} | <strong>Known Exploited (CISA KEV):</strong> {known_kev}</p>
    </section>
    <section class='panel grid'>
      <div>
        <h2>Severity Distribution</h2>
        <table>
          <thead><tr><th>Severity</th><th>Count</th></tr></thead>
          <tbody>{severity_rows or "<tr><td colspan='2'>No findings in this scope.</td></tr>"}</tbody>
        </table>
      </div>
      <div>
        <h2>Enterprise Assurance</h2>
        <table>
          <thead><tr><th>Metric</th><th>Value</th></tr></thead>
          <tbody>{enterprise_rows or "<tr><td colspan='2'>No enterprise assurance metrics available.</td></tr>"}</tbody>
        </table>
      </div>
    </section>
    <section class='panel'>
      <h2>Top Prioritized Findings</h2>
      <table>
        <thead><tr><th>ID</th><th>Severity</th><th>Issue</th><th>CVSS</th><th>Location</th><th>CWE</th><th>OWASP</th></tr></thead>
        <tbody>{top_rows or "<tr><td colspan='7'>No prioritized findings available for this scope.</td></tr>"}</tbody>
      </table>
    </section>
    <section class='panel'>
      <h2>Analyzer Runtime Breakdown</h2>
      <table>
        <thead><tr><th>Analyzer</th><th>Status</th><th>Attempted</th><th>Duration (ms)</th><th>Findings</th><th>Errors</th></tr></thead>
        <tbody>{timing_rows or "<tr><td colspan='6'>No analyzer runtime evidence available.</td></tr>"}</tbody>
      </table>
      <p class='meta'><strong>Implemented Controls:</strong> {existing.get('summary', {}).get('implemented_controls', 0)} | <strong>Findings:</strong> {vuln.get('summary', {}).get('total_findings', 0)}</p>
    </section>
    {benchmark_section}
  </main>
</body>
</html>
"""

