from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

from packaging.version import InvalidVersion, Version

from universal_security_scanner.models import Finding, Severity
from universal_security_scanner.scanner.rules.base import BaseProjectRule, RuleMetadata


@dataclass(frozen=True, slots=True)
class KnownVulnerability:
    package: str
    ecosystem: str
    affected_lt: str
    severity: Severity
    cve: str
    description: str
    recommendation: str
    reference: str


KNOWN_VULNERABLE_DEPS: list[KnownVulnerability] = [
    KnownVulnerability(
        package="django",
        ecosystem="python",
        affected_lt="2.2.24",
        severity=Severity.HIGH,
        cve="CVE-2021-33203",
        description="Potential SQL injection vectors in older Django versions.",
        recommendation="Upgrade Django to >=2.2.24 (or current LTS).",
        reference="https://nvd.nist.gov/vuln/detail/CVE-2021-33203",
    ),
    KnownVulnerability(
        package="pyyaml",
        ecosystem="python",
        affected_lt="5.4",
        severity=Severity.HIGH,
        cve="CVE-2020-14343",
        description="Arbitrary code execution risk via unsafe loader behavior in vulnerable versions.",
        recommendation="Upgrade PyYAML to >=5.4 and use safe loaders.",
        reference="https://nvd.nist.gov/vuln/detail/CVE-2020-14343",
    ),
    KnownVulnerability(
        package="urllib3",
        ecosystem="python",
        affected_lt="1.26.5",
        severity=Severity.MEDIUM,
        cve="CVE-2021-33503",
        description="Improper handling may lead to request smuggling in specific scenarios.",
        recommendation="Upgrade urllib3 to >=1.26.5.",
        reference="https://nvd.nist.gov/vuln/detail/CVE-2021-33503",
    ),
    KnownVulnerability(
        package="lodash",
        ecosystem="npm",
        affected_lt="4.17.21",
        severity=Severity.HIGH,
        cve="CVE-2021-23337",
        description="Command injection / prototype pollution issues in vulnerable lodash versions.",
        recommendation="Upgrade lodash to >=4.17.21.",
        reference="https://nvd.nist.gov/vuln/detail/CVE-2021-23337",
    ),
    KnownVulnerability(
        package="minimist",
        ecosystem="npm",
        affected_lt="1.2.6",
        severity=Severity.HIGH,
        cve="CVE-2021-44906",
        description="Prototype pollution vulnerability in minimist.",
        recommendation="Upgrade minimist to >=1.2.6.",
        reference="https://nvd.nist.gov/vuln/detail/CVE-2021-44906",
    ),
    KnownVulnerability(
        package="serialize-javascript",
        ecosystem="npm",
        affected_lt="3.1.0",
        severity=Severity.HIGH,
        cve="CVE-2020-7660",
        description="Cross-site scripting risk in vulnerable serialize-javascript versions.",
        recommendation="Upgrade serialize-javascript to >=3.1.0.",
        reference="https://nvd.nist.gov/vuln/detail/CVE-2020-7660",
    ),
]


_VERSION_PATTERN = re.compile(r"\d+(?:\.\d+){0,3}")


def _extract_version(spec: str) -> str | None:
    match = _VERSION_PATTERN.search(spec)
    return match.group(0) if match else None


def _is_affected(version: str, affected_lt: str) -> bool:
    try:
        return Version(version) < Version(affected_lt)
    except InvalidVersion:
        return False


def _find_line_number(path: Path, token: str) -> int:
    try:
        for number, line in enumerate(path.read_text(encoding="utf-8", errors="ignore").splitlines(), start=1):
            if token in line:
                return number
    except OSError:
        return 1
    return 1


def _parse_requirements(requirements_path: Path) -> list[tuple[str, str, int]]:
    parsed: list[tuple[str, str, int]] = []
    pattern = re.compile(r"^\s*([A-Za-z0-9_.-]+)\s*([<>=!~]{1,2}\s*[^;\s]+)?")

    for line_number, raw_line in enumerate(
        requirements_path.read_text(encoding="utf-8", errors="ignore").splitlines(), start=1
    ):
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue

        match = pattern.match(line)
        if not match:
            continue

        package = match.group(1).lower()
        spec = (match.group(2) or "").replace(" ", "")
        parsed.append((package, spec, line_number))

    return parsed


def _parse_package_json(package_json_path: Path) -> list[tuple[str, str, int]]:
    results: list[tuple[str, str, int]] = []
    data = json.loads(package_json_path.read_text(encoding="utf-8", errors="ignore"))

    for section in ("dependencies", "devDependencies", "peerDependencies"):
        deps = data.get(section, {})
        if not isinstance(deps, dict):
            continue
        for package, spec in deps.items():
            line_number = _find_line_number(package_json_path, f'"{package}"')
            results.append((package.lower(), str(spec), line_number))

    return results


class DependencyVulnerabilityRule(BaseProjectRule):
    metadata = RuleMetadata(
        rule_id="OWASP-A06-DEPENDENCY-001",
        vulnerability_type="Dependency Vulnerability",
        severity=Severity.HIGH,
        description="Dependencies include versions with known published vulnerabilities.",
        business_impact="Known vulnerable dependencies increase exploitability and breach likelihood.",
        recommendation="Upgrade vulnerable dependencies and enforce automated dependency auditing.",
        reference="https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
        owasp_category="A06:2021 - Vulnerable and Outdated Components",
        cwe="CWE-1104",
    )

    def scan_project(self, project_root: Path) -> list[Finding]:
        findings: list[Finding] = []

        requirements_path = project_root / "requirements.txt"
        if requirements_path.exists():
            findings.extend(self._scan_python_dependencies(requirements_path))

        package_json_path = project_root / "package.json"
        if package_json_path.exists():
            findings.extend(self._scan_npm_dependencies(package_json_path))

        return findings

    def _scan_python_dependencies(self, requirements_path: Path) -> list[Finding]:
        findings: list[Finding] = []
        for package, spec, line_number in _parse_requirements(requirements_path):
            version = _extract_version(spec)
            if version is None:
                continue

            for vuln in KNOWN_VULNERABLE_DEPS:
                if vuln.ecosystem != "python" or vuln.package != package:
                    continue
                if _is_affected(version, vuln.affected_lt):
                    evidence = f"{package}{spec}"
                    findings.append(
                        self._build_finding(
                            file_path=requirements_path,
                            line_number=line_number,
                            description=(
                                f"{package} version {version} is below safe threshold {vuln.affected_lt}. "
                                f"Known issue: {vuln.cve}."
                            ),
                            business_impact="Exploitable third-party components can lead to indirect compromise.",
                            recommendation=vuln.recommendation,
                            reference=vuln.reference,
                            owasp_category="A06:2021 - Vulnerable and Outdated Components",
                            cwe="CWE-1104",
                            severity=vuln.severity,
                            evidence=evidence,
                        )
                    )

        return findings

    def _scan_npm_dependencies(self, package_json_path: Path) -> list[Finding]:
        findings: list[Finding] = []
        try:
            dependencies = _parse_package_json(package_json_path)
        except json.JSONDecodeError:
            return findings

        for package, spec, line_number in dependencies:
            version = _extract_version(spec)
            if version is None:
                continue

            for vuln in KNOWN_VULNERABLE_DEPS:
                if vuln.ecosystem != "npm" or vuln.package != package:
                    continue
                if _is_affected(version, vuln.affected_lt):
                    evidence = f"{package}: {spec}"
                    findings.append(
                        self._build_finding(
                            file_path=package_json_path,
                            line_number=line_number,
                            description=(
                                f"{package} version {version} is below safe threshold {vuln.affected_lt}. "
                                f"Known issue: {vuln.cve}."
                            ),
                            business_impact="Client/server dependency weaknesses can be exploited at runtime.",
                            recommendation=vuln.recommendation,
                            reference=vuln.reference,
                            owasp_category="A06:2021 - Vulnerable and Outdated Components",
                            cwe="CWE-1104",
                            severity=vuln.severity,
                            evidence=evidence,
                        )
                    )

        return findings
