from __future__ import annotations

import argparse
import os
from pathlib import Path

from codesentinelx_engine.config import ScannerConfig
from codesentinelx_engine.logging_config import configure_logging
from codesentinelx_engine.scanner.engine import ScanEngine
from codesentinelx_engine.scanner.external import external_tool_names, prepare_toolchain
from codesentinelx_engine.scanner.remote_targets import (
    scan_remote_ssh_target,
    scan_runtime_http_target,
    scan_target,
)
from codesentinelx_engine.scanner.reporting.exporters import ReportExporter
from codesentinelx_engine.scanner.reporting.report_builder import build_report


def _cli_progress(progress: float, stage: str, current_file: str | None, message: str | None) -> None:
    detail = f" | {current_file}" if current_file else ""
    suffix = f" | {message}" if message else ""
    print(f"\r[{progress:6.2f}%] {stage}{detail}{suffix}", end="", flush=True)


def _resolve_export_path(
    format_name: str,
    user_output: str | None,
    config: ScannerConfig,
    report_type: str = "combined",
) -> Path:
    if user_output:
        return Path(user_output).expanduser().resolve()

    if not config.export_dir.is_absolute():
        export_dir = Path.cwd() / config.export_dir
    else:
        export_dir = config.export_dir

    export_dir.mkdir(parents=True, exist_ok=True)
    suffix = "" if report_type == "combined" else f"_{report_type}"
    return export_dir / f"security_report{suffix}.{format_name}"


def run_scan(
    path: str,
    fmt: str,
    output: str | None,
    report_type: str = "combined",
    split_reports: bool = False,
    show_progress: bool = True,
    target_type: str = "auto",
    auth_token: str | None = None,
    auth_cookie: str | None = None,
    auth_header_name: str | None = None,
    auth_header_value: str | None = None,
    role: str | None = None,
    pipeline: str = "legacy",
) -> int:
    config = ScannerConfig.from_env(role)
    configure_logging(config.log_level)

    progress = _cli_progress if show_progress else None
    if auth_token:
        os.environ["USS_RUNTIME_AUTH_TOKEN"] = auth_token.strip()
        import sys
        for i, arg in enumerate(sys.argv):
            if "auth-token" in arg and i + 1 < len(sys.argv):
                sys.argv[i + 1] = "***REDACTED***"
    if auth_cookie:
        os.environ["USS_RUNTIME_AUTH_COOKIE"] = auth_cookie.strip()
    if auth_header_name and auth_header_value:
        os.environ["USS_RUNTIME_AUTH_HEADER_NAME"] = auth_header_name.strip()
        os.environ["USS_RUNTIME_AUTH_HEADER_VALUE"] = auth_header_value.strip()
    normalized_target_type = target_type.strip().lower()
    if normalized_target_type == "auto":
        result = scan_target(path, config, progress_callback=progress)
    elif normalized_target_type == "local":
        engine = ScanEngine(config)
        result = engine.scan(path, progress_callback=progress)
    elif normalized_target_type == "http":
        result = scan_runtime_http_target(path, config=config, progress_callback=progress)
    elif normalized_target_type == "ssh":
        result = scan_remote_ssh_target(path, config, progress_callback=progress)
    else:
        raise ValueError(f"Unsupported target type: {target_type}")

    if show_progress:
        print("")

    if pipeline == "professional":
        from codesentinelx_engine.scanner.reporting.report_schema import ReportSchemaConverter
        from codesentinelx_engine.scanner.reporting.developer_report_renderer import DeveloperReportRenderer
        from codesentinelx_engine.scanner.reporting.report_models import ScanMetadata

        scan_meta = ScanMetadata(
            scan_id=result.target_path,
            scanner_version="2.0.0",
            target_path=result.target_path,
            files_scanned=result.files_scanned,
            total_lines_of_code=result.total_lines_of_code,
            duration_seconds=result.duration_seconds,
            started_at=result.started_at.isoformat() if result.started_at else "",
            completed_at=result.completed_at.isoformat() if result.completed_at else "",
            scan_environment="local",
            tools_used=list(result.toolchain_status.keys()) if result.toolchain_status else [],
            errors=result.errors,
        )

        converter = ReportSchemaConverter()
        renderer = DeveloperReportRenderer()
        dev_report = converter.build_developer_report(
            result.findings, result.target_path,
            project_name=Path(path).name or "CodeSentinelX Scan",
            scan_metadata=scan_meta,
        )
        html_content = renderer.render_html(dev_report)

        export_dir = config.export_dir
        if not export_dir.is_absolute():
            export_dir = (Path.cwd() / export_dir).resolve()
        export_dir.mkdir(parents=True, exist_ok=True)

        if output:
            output_path = Path(output).expanduser().resolve()
        else:
            output_path = export_dir / "developer_report.html"

        output_path.write_text(html_content, encoding="utf-8")
        print(f"Scan completed (professional pipeline)")
        print(f"Target: {result.target_path}")
        print(f"Total vulnerabilities: {len(result.findings)}")
        print(f"Exported report: {output_path}")
    else:
        report = build_report(result)
        export_dir = config.export_dir
        if not export_dir.is_absolute():
            export_dir = (Path.cwd() / export_dir).resolve()

        exporter = ReportExporter(export_dir)
        exported_paths: list[Path] = []

        if split_reports:
            if fmt.lower() == "sarif":
                raise ValueError("SARIF cannot be used with --split-reports. Use --report-type vulnerability for SARIF export.")
            if output:
                base = Path(output).expanduser().resolve()
                output_existing = base.with_name(f"{base.stem}_existing{base.suffix or f'.{fmt.lower()}'}")
                output_vuln = base.with_name(f"{base.stem}_vulnerability{base.suffix or f'.{fmt.lower()}'}")
                output_fixes = base.with_name(f"{base.stem}_fixes{base.suffix or f'.{fmt.lower()}'}")
                exported_paths.append(exporter.export(report, fmt.lower(), output_existing, report_type="existing"))
                exported_paths.append(exporter.export(report, fmt.lower(), output_vuln, report_type="vulnerability"))
                exported_paths.append(exporter.export(report, fmt.lower(), output_fixes, report_type="fixes"))
            else:
                output_existing = _resolve_export_path(fmt, None, config, report_type="existing")
                output_vuln = _resolve_export_path(fmt, None, config, report_type="vulnerability")
                output_fixes = _resolve_export_path(fmt, None, config, report_type="fixes")
                exported_paths.append(exporter.export(report, fmt.lower(), output_existing, report_type="existing"))
                exported_paths.append(exporter.export(report, fmt.lower(), output_vuln, report_type="vulnerability"))
                exported_paths.append(exporter.export(report, fmt.lower(), output_fixes, report_type="fixes"))
        else:
            if fmt.lower() == "sarif" and report_type.lower() in {"existing", "fixes"}:
                raise ValueError("SARIF is available only for vulnerability or combined report types.")
            output_path = _resolve_export_path(fmt, output, config, report_type=report_type.lower())
            exported_paths.append(exporter.export(report, fmt.lower(), output_path, report_type=report_type.lower()))

        summary = report["executive_summary"]
        print("Scan completed")
        print(f"Target: {summary['target_path']}")
        print(f"Files scanned: {summary['files_scanned']}")
        print(f"Total vulnerabilities: {summary['total_vulnerabilities']}")
        print(f"Risk score: {summary['risk_score']} ({summary['risk_rating']})")
        for exported in exported_paths:
            print(f"Exported report: {exported}")

    if result.errors:
        print("Warnings:")
        for err in result.errors[:10]:
            print(f"- {err}")

    return 0


def run_serve(host: str, port: int, reload_mode: bool) -> int:
    import uvicorn

    uvicorn.run("codesentinelx_engine.web.app:app", host=host, port=port, reload=reload_mode)
    return 0


def run_bootstrap_tools(path: str | None = None) -> int:
    config = ScannerConfig.from_env()
    configure_logging(config.log_level)

    root = Path(path).expanduser().resolve() if path else Path.cwd().resolve()
    tools = sorted(
        {
            tool
            for tool in (
                external_tool_names(config, target_mode="codebase", include_catalog=True)
                + external_tool_names(config, target_mode="runtime", include_catalog=True)
            )
            if tool != "runtime_http_probe"
        }
    )
    if not tools:
        print("No external tools configured. Set USS_EXTERNAL_TOOLS to enable integrations.")
        return 0

    print(f"Preparing toolchain in context: {root}")
    status_map = prepare_toolchain(config, tools, root)

    for tool in tools:
        status = status_map[tool]
        marker = "OK" if status.available else "MISSING"
        print(f"[{marker}] {tool} | source={status.source} | command={status.command}")
        if status.message:
            print(f"  -> {status.message}")

    missing = sum(1 for item in status_map.values() if not item.available)
    if missing > 0:
        print(f"Toolchain bootstrap completed with {missing} missing tools.")
        return 2

    print("Toolchain bootstrap completed successfully.")
    return 0


def run_bootstrap_tools_filtered(path: str | None = None, tools_csv: str | None = None, target_mode: str = "all") -> int:
    config = ScannerConfig.from_env()
    configure_logging(config.log_level)

    root = Path(path).expanduser().resolve() if path else Path.cwd().resolve()
    explicit_tools = [item.strip().lower() for item in (tools_csv or "").split(",") if item.strip()]
    if explicit_tools:
        tools = sorted({tool for tool in explicit_tools if tool != "runtime_http_probe"})
    else:
        if target_mode == "codebase":
            tools = sorted(set(external_tool_names(config, target_mode="codebase", include_catalog=True)))
        elif target_mode == "runtime":
            tools = sorted(set(external_tool_names(config, target_mode="runtime", include_catalog=True)))
        else:
            tools = sorted(
                {
                    tool
                    for tool in (
                        external_tool_names(config, target_mode="codebase", include_catalog=True)
                        + external_tool_names(config, target_mode="runtime", include_catalog=True)
                    )
                }
            )
        tools = [tool for tool in tools if tool != "runtime_http_probe"]

    if not tools:
        print("No tools selected for bootstrap.")
        return 0

    print(f"Preparing toolchain in context: {root}")
    status_map = prepare_toolchain(config, tools, root)

    for tool in tools:
        status = status_map[tool]
        marker = "OK" if status.available else "MISSING"
        print(f"[{marker}] {tool} | source={status.source} | command={status.command}")
        if status.message:
            print(f"  -> {status.message}")

    missing = sum(1 for item in status_map.values() if not item.available)
    if missing > 0:
        print(f"Toolchain bootstrap completed with {missing} missing tools.")
        return 2

    print("Toolchain bootstrap completed successfully.")
    return 0


def run_generate_report(
    input_path: str,
    output_path: str | None,
    project_name: str = "CodeSentinelX Scan",
) -> int:
    import json

    from codesentinelx_engine.models import Finding, Severity
    from codesentinelx_engine.scanner.reporting.report_schema import ReportSchemaConverter
    from codesentinelx_engine.scanner.reporting.developer_report_renderer import DeveloperReportRenderer
    from codesentinelx_engine.scanner.reporting.report_models import ScanMetadata

    input_file = Path(input_path).expanduser().resolve()
    if not input_file.exists():
        print(f"Error: Input file not found: {input_file}")
        return 1

    raw = json.loads(input_file.read_text(encoding="utf-8"))

    findings_data: list[dict] = []
    target_path = ""
    if isinstance(raw, dict):
        target_path = str(
            raw.get("target_path")
            or raw.get("vulnerability_fixed_code_report", {}).get("target_path", "")
        )
        findings_data = raw.get("findings") or raw.get(
            "vulnerability_fixed_code_report", {}
        ).get("findings", [])
    elif isinstance(raw, list):
        findings_data = raw

    findings: list[Finding] = []
    for fd in findings_data:
        sev_raw = str(fd.get("severity") or "Info")
        try:
            sev = Severity(sev_raw)
        except ValueError:
            sev = Severity.INFO
        findings.append(Finding(
            vulnerability_type=fd.get("vulnerability_type") or fd.get("title") or fd.get("rule_id", "Unknown"),
            severity=sev,
            file_path=fd.get("file_path") or fd.get("path", ""),
            line_number=int(fd.get("line_number") or fd.get("line") or 0),
            business_impact=fd.get("business_impact") or fd.get("description", ""),
            recommendation=fd.get("recommendation") or fd.get("fix", ""),
            reference=fd.get("reference", ""),
            owasp_category=fd.get("owasp_category") or fd.get("owasp_mapping", ""),
            description=fd.get("description") or fd.get("business_impact", ""),
            rule_id=fd.get("rule_id") or fd.get("id", ""),
            cwe=fd.get("cwe") or fd.get("cwe_id"),
            cvss_score=fd.get("cvss_score"),
            cvss_vector=fd.get("cvss_vector"),
        ))

    scan_meta = ScanMetadata(
        scan_id=target_path,
        scanner_version="2.0.0",
        target_path=target_path,
        files_scanned=raw.get("files_scanned", 0) if isinstance(raw, dict) else 0,
        total_lines_of_code=raw.get("total_lines_of_code", 0) if isinstance(raw, dict) else 0,
        duration_seconds=float(raw.get("duration_seconds", 0)) if isinstance(raw, dict) else 0.0,
        errors=raw.get("errors", []) if isinstance(raw, dict) else [],
    )

    converter = ReportSchemaConverter()
    renderer = DeveloperReportRenderer()
    dev_report = converter.build_developer_report(
        findings, target_path, project_name=project_name,
        scan_metadata=scan_meta,
    )
    html_content = renderer.render_html(dev_report)

    if output_path:
        out = Path(output_path).expanduser().resolve()
    else:
        out = input_file.with_suffix(".professional.html")

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(html_content, encoding="utf-8")
    print(f"Professional report generated: {out}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="codesentinelx",
        description="CodeSentinelX CLI",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Run a security scan")
    scan_parser.add_argument("--path", required=True, help="Target project file or folder path")
    scan_parser.add_argument(
        "--target-type",
        default="auto",
        choices=["auto", "local", "http", "ssh"],
        help="Target mode: auto-detect, local path scan, remote HTTP scan, or remote SSH code scan",
    )
    scan_parser.add_argument(
        "--format",
        default="json",
        choices=["json", "html", "pdf", "sarif", "markdown", "csv"],
        help="Report export format",
    )
    scan_parser.add_argument(
        "--report-type",
        default="combined",
        choices=["combined", "existing", "vulnerability", "fixes"],
        help="Report content type to export",
    )
    scan_parser.add_argument(
        "--role",
        default=os.getenv("USS_SCAN_ROLE", "Security Analyst"),
        choices=["Admin", "Security Analyst", "Developer", "Auditor", "Management"],
        help="Role scope to apply to scan execution and report output",
    )
    scan_parser.add_argument(
        "--split-reports",
        action="store_true",
        help="Export three separate reports (existing + vulnerability + fixes) in one run",
    )
    scan_parser.add_argument("--output", help="Output file path for exported report")
    scan_parser.add_argument(
        "--no-progress",
        action="store_true",
        help="Disable CLI progress updates",
    )
    scan_parser.add_argument("--auth-token", help="Runtime authenticated crawl: bearer token value without prefix")
    scan_parser.add_argument("--auth-cookie", help="Runtime authenticated crawl: cookie header value")
    scan_parser.add_argument("--auth-header-name", help="Runtime authenticated crawl: custom header name")
    scan_parser.add_argument("--auth-header-value", help="Runtime authenticated crawl: custom header value")
    scan_parser.add_argument(
        "--pipeline",
        default="legacy",
        choices=["legacy", "professional"],
        help="Report pipeline: 'legacy' (default) or 'professional' (new HTML-based pipeline)",
    )

    serve_parser = subparsers.add_parser("serve", help="Run interactive web UI")
    serve_parser.add_argument("--host", default="127.0.0.1", help="Host interface")
    serve_parser.add_argument("--port", default=8000, type=int, help="Port")
    serve_parser.add_argument("--reload", action="store_true", help="Enable auto-reload")

    bootstrap_parser = subparsers.add_parser(
        "bootstrap-tools",
        help="Auto-install/prepare external scanning tools",
    )
    bootstrap_parser.add_argument("--path", help="Project path context for local tool cache placement")
    bootstrap_parser.add_argument(
        "--tools",
        help="Comma separated list of tools to bootstrap/check (e.g. semgrep,trivy,codeql)",
    )
    bootstrap_parser.add_argument(
        "--target-mode",
        default="all",
        choices=["all", "codebase", "runtime"],
        help="Bootstrap by target profile when --tools is not provided",
    )

    report_parser = subparsers.add_parser(
        "generate-report",
        help="Generate professional HTML report from existing scan JSON output",
    )
    report_parser.add_argument(
        "--input",
        required=True,
        help="Path to JSON scan output file (UniversalScanReport format)",
    )
    report_parser.add_argument(
        "--output",
        help="Output file path for generated HTML report",
    )
    report_parser.add_argument(
        "--project-name",
        default="CodeSentinelX Scan",
        help="Project name to display in the report",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        return run_scan(
            args.path,
            args.format,
            args.output,
            report_type=args.report_type,
            split_reports=args.split_reports,
            show_progress=not args.no_progress,
            target_type=args.target_type,
            auth_token=args.auth_token,
            auth_cookie=args.auth_cookie,
            auth_header_name=args.auth_header_name,
            auth_header_value=args.auth_header_value,
            role=args.role,
            pipeline=args.pipeline,
        )
    elif args.command == "serve":
        return run_serve(args.host, args.port, args.reload)
    elif args.command == "bootstrap-tools":
        if args.tools or args.target_mode != "all":
            return run_bootstrap_tools_filtered(args.path, args.tools, args.target_mode)
        return run_bootstrap_tools(args.path)
    elif args.command == "generate-report":
        return run_generate_report(
            args.input,
            args.output,
            project_name=args.project_name,
        )

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())



