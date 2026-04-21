from __future__ import annotations

from pathlib import Path
from typing import Any

from codesentinelx_engine.models import Finding
from codesentinelx_engine.scanner.external.common import (
    extract_cwe,
    first_reference,
    iter_files,
    normalize_path,
    run_command,
    safe_json_loads,
    to_severity,
)


def _iter_checkov_documents(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, dict):
        return [payload]
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    return []


def _discover_checkov_targets(target_root: Path) -> list[Path]:
    targets: list[Path] = []
    for path in iter_files(target_root):
        lower_name = path.name.lower()
        suffix = path.suffix.lower()
        if lower_name == "dockerfile" or lower_name.startswith("dockerfile.") or suffix == ".dockerfile":
            targets.append(path)
            continue
        if suffix in {".tf", ".tfvars"} or path.name.lower().endswith(".tf.json") or path.name.lower().endswith(".tfvars.json"):
            targets.append(path)
            continue
        if suffix in {".yaml", ".yml", ".json"} and any(token in lower_name for token in ("k8s", "kubernetes", "helm", "chart", "deployment", "service", "pod", "ingress", "namespace", "configmap", "secret", "statefulset", "daemonset", "job", "cronjob", "clusterrole", "rolebinding", "role", "rbac", "template", "cfn", "cloudformation")):
            targets.append(path)
    deduped: list[Path] = []
    seen: set[str] = set()
    for target in sorted(targets):
        key = str(target)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(target)
    return deduped


def parse_checkov_output(data: Any, target_root: Path) -> list[Finding]:
    findings: list[Finding] = []
    documents = _iter_checkov_documents(data)

    for document in documents:
        check_type = str(document.get("check_type") or "iac")
        results = document.get("results") or {}
        failed_checks = results.get("failed_checks") or []
        if not isinstance(failed_checks, list):
            continue

        for check in failed_checks:
            if not isinstance(check, dict):
                continue

            check_id = str(check.get("check_id") or "UNKNOWN")
            title = str(check.get("check_name") or f"Checkov policy {check_id}")
            severity = to_severity(str(check.get("severity") or "medium"))

            raw_path = str(check.get("file_abs_path") or check.get("file_path") or "unknown")
            if raw_path and not Path(raw_path).is_absolute():
                raw_path = raw_path.lstrip("/\\")
            file_path = normalize_path(target_root, raw_path)

            line_range = check.get("file_line_range") or []
            if isinstance(line_range, list) and line_range:
                line_number = int(line_range[0] or 1)
            else:
                line_number = int(check.get("line_number") or 1)

            guideline = str(check.get("guideline") or "").strip()
            reference = first_reference([guideline], f"https://www.checkov.io/5.Policy%20Index/{check_type}.html")
            cwe = extract_cwe([guideline, check.get("description"), check.get("check_name"), check.get("bc_category")])

            entity = check.get("check_result", {}).get("entity")
            evidence = None
            if entity:
                evidence = str(entity)[:240]

            findings.append(
                Finding(
                    vulnerability_type=f"IaC Policy Violation ({check_type})",
                    severity=severity,
                    file_path=file_path,
                    line_number=max(1, line_number),
                    business_impact=(
                        "Infrastructure misconfiguration can expose cloud resources and weaken security controls."
                    ),
                    recommendation=(
                        guideline
                        or "Apply Checkov remediation guidance and enforce policy checks in CI/CD before deployment."
                    ),
                    reference=reference,
                    owasp_category="A05:2021 - Security Misconfiguration",
                    description=title,
                    rule_id=f"CHECKOV-{check_id}",
                    cwe=cwe or "CWE-16",
                    evidence=evidence,
                )
            )

    return findings


def run_checkov_scan(
    target_root: Path,
    timeout_seconds: int,
    binary: str = "checkov",
) -> tuple[list[Finding], list[str]]:
    targets = _discover_checkov_targets(target_root)
    if not targets:
        return [], []

    findings: list[Finding] = []
    errors: list[str] = []
    per_file_timeout = max(30, min(timeout_seconds, 180))

    for target in targets:
        command = [
            binary,
            "-f",
            str(target),
            "--quiet",
            "--compact",
            "-o",
            "json",
        ]

        try:
            return_code, stdout, stderr = run_command(command, timeout_seconds=per_file_timeout)
        except FileNotFoundError:
            return [], ["Checkov not found in PATH/toolchain. Install or bootstrap Checkov for IaC scanning coverage."]
        except Exception as exc:
            errors.append(f"{target.name}: Checkov execution failed: {exc}")
            continue

        if return_code not in {0, 1}:
            short_error = " | ".join((stderr or "").strip().splitlines()[:3])
            errors.append(f"{target.name}: Checkov returned code {return_code}: {short_error}")
            continue

        payload = safe_json_loads(stdout)
        if payload is None:
            short_error = " | ".join((stderr or "").strip().splitlines()[:3])
            errors.append(f"{target.name}: Checkov produced non-JSON output. {short_error}".strip())
            continue

        findings.extend(parse_checkov_output(payload, target_root))

    return findings, errors

