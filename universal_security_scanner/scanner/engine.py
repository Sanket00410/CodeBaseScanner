from __future__ import annotations

import logging
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

from universal_security_scanner.config import ScannerConfig
from universal_security_scanner.models import Finding, SEVERITY_ORDER, ScanResult
from universal_security_scanner.plugins import load_builtin_language_plugins
from universal_security_scanner.scanner.controls import ExistingSecurityMeasuresAnalyzer
from universal_security_scanner.scanner.external import (
    discover_toolchain,
    external_tool_names,
    prepare_toolchain,
    run_external_tool,
    supported_runner_tools,
    tool_metadata,
)
from universal_security_scanner.scanner.file_discovery import discover_files
from universal_security_scanner.scanner.rules.registry import build_file_rules, build_project_rules

LOGGER = logging.getLogger(__name__)

ProgressCallback = Callable[[float, str, str | None, str | None], None]


class ScanEngine:
    def __init__(self, config: ScannerConfig) -> None:
        self.config = config
        self.file_rules = build_file_rules()
        self.project_rules = build_project_rules()
        self.plugins = load_builtin_language_plugins()

    def scan(self, target_path: str | Path, progress_callback: ProgressCallback | None = None) -> ScanResult:
        target = Path(target_path).expanduser().resolve()
        if not target.exists() or not target.is_dir():
            raise FileNotFoundError(f"Target path does not exist or is not a directory: {target}")

        started_at = datetime.now(timezone.utc)
        files = discover_files(target, self.config)
        findings: list[Finding] = []
        errors: list[str] = []
        seen: set[tuple[str, str, int, str | None]] = set()
        active_external_tools = external_tool_names(self.config, target_mode="codebase")
        catalog_tools = external_tool_names(self.config, target_mode="codebase", include_catalog=True)
        runner_supported = set(supported_runner_tools("codebase"))
        selected_runner_tools = [tool for tool in active_external_tools if tool in runner_supported]
        control_analyzer = ExistingSecurityMeasuresAnalyzer()
        toolchain_status: dict[str, dict[str, object]] = {}
        findings_limit = self.config.max_findings

        def findings_limit_reached() -> bool:
            return findings_limit > 0 and len(findings) >= findings_limit

        def append_finding(candidate: Finding) -> None:
            dedupe_key = (
                candidate.rule_id,
                candidate.file_path,
                candidate.line_number,
                candidate.evidence,
            )
            if dedupe_key in seen:
                return
            seen.add(dedupe_key)
            findings.append(candidate)

        toolchain_prepare_steps = 1 if active_external_tools or catalog_tools else 0
        total_steps = max(1, len(files) + len(self.project_rules) + len(selected_runner_tools) + toolchain_prepare_steps)
        completed_steps = 0

        if progress_callback:
            progress_callback(0.0, "discovering", None, f"Discovered {len(files)} files")

        for index, path in enumerate(files, start=1):
            relative_path = path.relative_to(target)
            completed_steps += 1
            progress = round((completed_steps / total_steps) * 100.0, 2)

            if progress_callback:
                progress_callback(
                    progress,
                    "scanning_files",
                    str(relative_path),
                    f"Scanning file {index}/{len(files)}",
                )

            try:
                content = path.read_text(encoding="utf-8", errors="ignore")
            except OSError as exc:
                error = f"Unable to read {relative_path}: {exc}"
                LOGGER.warning(error)
                errors.append(error)
                continue

            control_analyzer.observe_file(relative_path, content)

            for rule in self.file_rules:
                if findings_limit_reached():
                    errors.append("Maximum findings limit reached; remaining checks skipped.")
                    break

                try:
                    rule_findings = rule.scan_file(relative_path, content)
                except Exception as exc:  # pragma: no cover - defensive branch
                    error = f"Rule {rule.metadata.rule_id} failed on {relative_path}: {exc}"
                    LOGGER.exception(error)
                    errors.append(error)
                    continue

                for finding in rule_findings:
                    append_finding(finding)

            for plugin in self.plugins:
                if findings_limit_reached():
                    errors.append("Maximum findings limit reached; plugin checks skipped.")
                    break
                if not plugin.supports(relative_path):
                    continue

                try:
                    plugin_findings = plugin.scan_file(relative_path, content)
                except Exception as exc:  # pragma: no cover - defensive branch
                    error = f"Plugin {plugin.metadata.plugin_id} failed on {relative_path}: {exc}"
                    LOGGER.exception(error)
                    errors.append(error)
                    continue

                for finding in plugin_findings:
                    append_finding(finding)

            if findings_limit_reached():
                break

        for project_rule in self.project_rules:
            completed_steps += 1
            progress = round((completed_steps / total_steps) * 100.0, 2)
            if progress_callback:
                progress_callback(
                    progress,
                    "scanning_dependencies",
                    str(target),
                    f"Running {project_rule.metadata.rule_id}",
                )

            try:
                project_findings = project_rule.scan_project(target)
            except Exception as exc:  # pragma: no cover - defensive branch
                error = f"Project rule {project_rule.metadata.rule_id} failed: {exc}"
                LOGGER.exception(error)
                errors.append(error)
                continue

            for finding in project_findings:
                normalized_path = finding.file_path
                try:
                    normalized_path = str(Path(finding.file_path).resolve().relative_to(target))
                except Exception:
                    pass

                normalized = Finding(
                    vulnerability_type=finding.vulnerability_type,
                    severity=finding.severity,
                    file_path=normalized_path,
                    line_number=finding.line_number,
                    business_impact=finding.business_impact,
                    recommendation=finding.recommendation,
                    reference=finding.reference,
                    owasp_category=finding.owasp_category,
                    description=finding.description,
                    rule_id=finding.rule_id,
                    cwe=finding.cwe,
                    evidence=finding.evidence,
                )
                append_finding(normalized)

        if active_external_tools or catalog_tools:
            completed_steps += 1
            progress = round((completed_steps / total_steps) * 100.0, 2)
            if progress_callback:
                progress_callback(
                    progress,
                    "preparing_toolchain",
                    str(target),
                    "Preparing external scanning toolchain",
                )

            discovered_toolchain = discover_toolchain(self.config, catalog_tools, Path.cwd())
            selected_toolchain = prepare_toolchain(
                self.config,
                active_external_tools,
                Path.cwd(),
                allow_bootstrap=self.config.auto_bootstrap_tools,
            )

            merged_tools = sorted(set(catalog_tools) | set(active_external_tools))
            for tool_name in merged_tools:
                discovered_status = discovered_toolchain.get(tool_name)
                selected_status = selected_toolchain.get(tool_name)
                chosen_status = selected_status or discovered_status
                metadata = tool_metadata(tool_name)

                status_payload: dict[str, object]
                if chosen_status:
                    status_payload = chosen_status.to_dict()
                else:
                    status_payload = {
                        "name": tool_name,
                        "available": False,
                        "command": tool_name,
                        "source": "missing",
                        "message": "Tool was not evaluated for this scan profile.",
                    }
                status_payload.update(metadata)
                status_payload["selected"] = tool_name in active_external_tools
                status_payload["runner_available"] = tool_name in runner_supported

                if tool_name in active_external_tools and tool_name in runner_supported and selected_status and not selected_status.available:
                    errors.append(f"[{tool_name}] {selected_status.message}")
                if tool_name in active_external_tools and tool_name not in runner_supported:
                    status_payload["message"] = (
                        "Tool discovered in catalog, but normalized finding ingestion is not implemented yet."
                    )

                toolchain_status[tool_name] = status_payload

        for tool_name in selected_runner_tools:
            status = toolchain_status.get(tool_name, {})
            completed_steps += 1
            progress = round((completed_steps / total_steps) * 100.0, 2)
            if progress_callback:
                progress_callback(
                    progress,
                    "scanning_external",
                    str(target),
                    f"Running external analyzer: {tool_name}",
                )

            if not bool(status.get("available", False)):
                continue

            if findings_limit_reached():
                errors.append("Maximum findings limit reached; external checks skipped.")
                break

            tool_findings, tool_errors = run_external_tool(
                tool_name,
                target_root=target,
                config=self.config,
                command=str(status.get("command") or tool_name),
            )
            for error in tool_errors:
                errors.append(f"[{tool_name}] {error}")

            for finding in tool_findings:
                normalized_path = finding.file_path
                try:
                    normalized_path = str(Path(finding.file_path).resolve().relative_to(target))
                except Exception:
                    pass

                normalized = Finding(
                    vulnerability_type=finding.vulnerability_type,
                    severity=finding.severity,
                    file_path=normalized_path,
                    line_number=finding.line_number,
                    business_impact=finding.business_impact,
                    recommendation=finding.recommendation,
                    reference=finding.reference,
                    owasp_category=finding.owasp_category,
                    description=finding.description,
                    rule_id=finding.rule_id,
                    cwe=finding.cwe,
                    evidence=finding.evidence,
                )
                append_finding(normalized)

        findings.sort(key=lambda item: (SEVERITY_ORDER[item.severity], item.file_path, item.line_number))

        completed_at = datetime.now(timezone.utc)
        if progress_callback:
            progress_callback(100.0, "completed", None, "Scan completed")

        return ScanResult(
            target_path=str(target),
            started_at=started_at,
            completed_at=completed_at,
            files_scanned=len(files),
            findings=findings,
            errors=errors,
            existing_security_measures=control_analyzer.finalize(total_files=len(files)),
            toolchain_status=toolchain_status,
        )
