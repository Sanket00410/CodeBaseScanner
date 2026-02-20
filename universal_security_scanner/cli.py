from __future__ import annotations

import argparse
import os
from pathlib import Path

from universal_security_scanner.config import ScannerConfig
from universal_security_scanner.logging_config import configure_logging
from universal_security_scanner.scanner.engine import ScanEngine
from universal_security_scanner.scanner.external import external_tool_names, prepare_toolchain
from universal_security_scanner.scanner.remote_targets import (
    scan_remote_ssh_target,
    scan_runtime_http_target,
    scan_target,
)
from universal_security_scanner.scanner.reporting.exporters import ReportExporter
from universal_security_scanner.scanner.reporting.report_builder import build_report


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
) -> int:
    config = ScannerConfig.from_env()
    configure_logging(config.log_level)

    progress = _cli_progress if show_progress else None
    if auth_token:
        os.environ["USS_RUNTIME_AUTH_TOKEN"] = auth_token.strip()
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

    uvicorn.run("universal_security_scanner.web.app:app", host=host, port=port, reload=reload_mode)
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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="uss",
        description="Universal Security Scanner CLI",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Run a security scan")
    scan_parser.add_argument("--path", required=True, help="Target project folder path")
    scan_parser.add_argument(
        "--target-type",
        default="auto",
        choices=["auto", "local", "http", "ssh"],
        help="Target mode: auto-detect, local path scan, remote HTTP scan, or remote SSH code scan",
    )
    scan_parser.add_argument(
        "--format",
        default="json",
        choices=["json", "html", "pdf", "sarif"],
        help="Report export format",
    )
    scan_parser.add_argument(
        "--report-type",
        default="combined",
        choices=["combined", "existing", "vulnerability", "fixes"],
        help="Report content type to export",
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
        )

    if args.command == "serve":
        return run_serve(args.host, args.port, args.reload)

    if args.command == "bootstrap-tools":
        if args.tools or args.target_mode != "all":
            return run_bootstrap_tools_filtered(args.path, args.tools, args.target_mode)
        return run_bootstrap_tools(args.path)

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
