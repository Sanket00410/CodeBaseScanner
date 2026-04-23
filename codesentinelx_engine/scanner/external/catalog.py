from __future__ import annotations

from dataclasses import dataclass


TargetMode = str


@dataclass(frozen=True, slots=True)
class ToolCatalogEntry:
    name: str
    display_name: str
    description: str
    category: str
    command: str
    target_modes: tuple[TargetMode, ...]
    vulnerability_classes: tuple[str, ...]
    homepage: str
    integrated: bool


TOOL_CATALOG: dict[str, ToolCatalogEntry] = {
    # Unified runtime probe
    "runtime_http_probe": ToolCatalogEntry(
        name="runtime_http_probe",
        display_name="Runtime HTTP Probe",
        description="Built-in HTTP probe that checks headers, exposed endpoints, CORS, and transport posture.",
        category="Application Runtime Scanning",
        command="builtin",
        target_modes=("runtime",),
        vulnerability_classes=(
            "Security Misconfiguration",
            "Broken Access Control",
            "Cryptographic Failures",
            "Information Disclosure",
        ),
        homepage="https://owasp.org/www-project-top-ten/",
        integrated=True,
    ),
    # Core integrated code analyzers
    "semgrep": ToolCatalogEntry(
        name="semgrep",
        display_name="Semgrep",
        description="Semantic SAST engine across multiple languages with security rules and taint-style detections.",
        category="SAST / Semantic Analysis",
        command="semgrep",
        target_modes=("codebase", "remote-codebase"),
        vulnerability_classes=(
            "Injection",
            "XSS",
            "Command Injection",
            "Insecure Deserialization",
            "Authentication/Authorization",
            "Unsafe Eval",
        ),
        homepage="https://semgrep.dev/",
        integrated=True,
    ),
    "codeql": ToolCatalogEntry(
        name="codeql",
        display_name="CodeQL",
        description="Data-flow and semantic query engine for security and quality checks with CodeQL query packs.",
        category="SAST / Dataflow Analysis",
        command="codeql",
        target_modes=("codebase", "remote-codebase"),
        vulnerability_classes=(
            "Injection",
            "Memory Safety",
            "Deserialization",
            "Authentication/Authorization",
            "Race Conditions",
        ),
        homepage="https://codeql.github.com/",
        integrated=True,
    ),
    "trivy": ToolCatalogEntry(
        name="trivy",
        display_name="Trivy",
        description="Dependency, secret, and misconfiguration scanner for source trees and IaC.",
        category="Dependency / Misconfiguration",
        command="trivy",
        target_modes=("codebase", "remote-codebase"),
        vulnerability_classes=(
            "Dependency Vulnerabilities",
            "Misconfigurations",
            "Hardcoded Secrets",
        ),
        homepage="https://aquasecurity.github.io/trivy/",
        integrated=True,
    ),
    "gitleaks": ToolCatalogEntry(
        name="gitleaks",
        display_name="Gitleaks",
        description="High-signal scanner for API keys, tokens, and credential leaks in repositories.",
        category="Secret Scanning",
        command="gitleaks",
        target_modes=("codebase", "remote-codebase"),
        vulnerability_classes=("Hardcoded Secrets",),
        homepage="https://github.com/gitleaks/gitleaks",
        integrated=True,
    ),
    "bandit": ToolCatalogEntry(
        name="bandit",
        display_name="Bandit",
        description="Python-focused AST security linter for common insecure patterns and APIs.",
        category="Language-Specific SAST",
        command="bandit",
        target_modes=("codebase", "remote-codebase"),
        vulnerability_classes=(
            "Command Injection",
            "Unsafe Eval",
            "Insecure Cryptography",
            "Deserialization",
        ),
        homepage="https://bandit.readthedocs.io/",
        integrated=True,
    ),
    # Runtime external analyzers
    "nuclei": ToolCatalogEntry(
        name="nuclei",
        display_name="Nuclei",
        description="Template-based runtime scanner for CVE, misconfiguration, exposure, and takeover checks.",
        category="Application Runtime Scanning",
        command="nuclei",
        target_modes=("runtime",),
        vulnerability_classes=(
            "Known CVEs",
            "Misconfigurations",
            "Exposed Services",
            "Authentication/Authorization",
        ),
        homepage="https://nuclei.projectdiscovery.io/",
        integrated=True,
    ),
    "nikto": ToolCatalogEntry(
        name="nikto",
        display_name="Nikto",
        description="Web server scanner focused on dangerous files, default configs, and outdated software.",
        category="Application Runtime Scanning",
        command="nikto",
        target_modes=("runtime",),
        vulnerability_classes=(
            "Security Misconfiguration",
            "Information Disclosure",
            "Outdated Components",
        ),
        homepage="https://cirt.net/Nikto2",
        integrated=True,
    ),
    "nmap": ToolCatalogEntry(
        name="nmap",
        display_name="Nmap NSE Vuln Scripts",
        description="Network service discovery and vulnerability script execution against exposed runtime targets.",
        category="Network Exposure Scanning",
        command="nmap",
        target_modes=("runtime",),
        vulnerability_classes=(
            "Exposed Services",
            "Known CVEs",
            "Insecure Network Services",
        ),
        homepage="https://nmap.org/",
        integrated=True,
    ),
    "zap-baseline": ToolCatalogEntry(
        name="zap-baseline",
        display_name="OWASP ZAP Baseline",
        description="Passive web security checks for runtime endpoints including headers and common web weaknesses.",
        category="DAST / Web Security",
        command="zap-baseline.py",
        target_modes=("runtime",),
        vulnerability_classes=(
            "OWASP Top 10",
            "Security Misconfiguration",
            "Injection",
            "XSS",
        ),
        homepage="https://www.zaproxy.org/",
        integrated=True,
    ),
    # Catalog-only (detected and documented in UI/toolchain matrix)
    "owasp-dependency-check": ToolCatalogEntry(
        name="owasp-dependency-check",
        display_name="OWASP Dependency-Check",
        description="SCA scanner mapping vulnerable dependencies to CVE/CPE intelligence.",
        category="Dependency / SCA",
        command="dependency-check",
        target_modes=("codebase", "remote-codebase"),
        vulnerability_classes=("Dependency Vulnerabilities",),
        homepage="https://owasp.org/www-project-dependency-check/",
        integrated=True,
    ),
    "sonarqube": ToolCatalogEntry(
        name="sonarqube",
        display_name="SonarQube",
        description="Code quality and security analyzer with customizable quality gates and rules.",
        category="SAST Platform",
        command="sonar-scanner",
        target_modes=("codebase", "remote-codebase"),
        vulnerability_classes=(
            "Injection",
            "Insecure Coding Patterns",
            "Business Logic Risks",
        ),
        homepage="https://www.sonarsource.com/products/sonarqube/",
        integrated=True,
    ),
    "snyk": ToolCatalogEntry(
        name="snyk",
        display_name="Snyk",
        description="SCA and container vulnerability scanning platform with remediation guidance.",
        category="Dependency / SCA",
        command="snyk",
        target_modes=("codebase", "remote-codebase"),
        vulnerability_classes=("Dependency Vulnerabilities", "Misconfigurations"),
        homepage="https://snyk.io/",
        integrated=True,
    ),
    "osv-scanner": ToolCatalogEntry(
        name="osv-scanner",
        display_name="OSV-Scanner",
        description="Open Source Vulnerability (OSV) based dependency vulnerability scanner.",
        category="Dependency / SCA",
        command="osv-scanner",
        target_modes=("codebase", "remote-codebase"),
        vulnerability_classes=("Dependency Vulnerabilities",),
        homepage="https://google.github.io/osv-scanner/",
        integrated=True,
    ),
    "grype": ToolCatalogEntry(
        name="grype",
        display_name="Grype",
        description="Vulnerability scanner for source, packages, and container artifacts.",
        category="Dependency / SCA",
        command="grype",
        target_modes=("codebase", "remote-codebase"),
        vulnerability_classes=("Dependency Vulnerabilities",),
        homepage="https://github.com/anchore/grype",
        integrated=True,
    ),
    "pip-audit": ToolCatalogEntry(
        name="pip-audit",
        display_name="pip-audit",
        description="Python dependency vulnerability scanner for requirements and installed packages.",
        category="Dependency / SCA",
        command="pip-audit",
        target_modes=("codebase", "remote-codebase"),
        vulnerability_classes=("Dependency Vulnerabilities",),
        homepage="https://github.com/pypa/pip-audit",
        integrated=True,
    ),
    "safety": ToolCatalogEntry(
        name="safety",
        display_name="Safety",
        description="Python dependency security scanner against vulnerability advisories.",
        category="Dependency / SCA",
        command="safety",
        target_modes=("codebase", "remote-codebase"),
        vulnerability_classes=("Dependency Vulnerabilities",),
        homepage="https://pyup.io/safety/",
        integrated=True,
    ),
    "npm-audit": ToolCatalogEntry(
        name="npm-audit",
        display_name="npm audit",
        description="Node package vulnerability audit using npm advisory database.",
        category="Dependency / SCA",
        command="npm",
        target_modes=("codebase", "remote-codebase"),
        vulnerability_classes=("Dependency Vulnerabilities",),
        homepage="https://docs.npmjs.com/cli/v10/commands/npm-audit",
        integrated=True,
    ),
    "govulncheck": ToolCatalogEntry(
        name="govulncheck",
        display_name="govulncheck",
        description="Go vulnerability scanner with call-trace-aware reporting.",
        category="Language-Specific SAST",
        command="govulncheck",
        target_modes=("codebase", "remote-codebase"),
        vulnerability_classes=("Dependency Vulnerabilities", "Code-level Reachability"),
        homepage="https://go.dev/doc/security/vuln/",
        integrated=True,
    ),
    "gosec": ToolCatalogEntry(
        name="gosec",
        display_name="gosec",
        description="Go static analyzer for insecure coding practices and misuse patterns.",
        category="Language-Specific SAST",
        command="gosec",
        target_modes=("codebase", "remote-codebase"),
        vulnerability_classes=("Injection", "Crypto Misuse", "Hardcoded Secrets"),
        homepage="https://github.com/securego/gosec",
        integrated=True,
    ),
    "brakeman": ToolCatalogEntry(
        name="brakeman",
        display_name="Brakeman",
        description="Ruby on Rails static scanner for common web security flaws.",
        category="Language-Specific SAST",
        command="brakeman",
        target_modes=("codebase", "remote-codebase"),
        vulnerability_classes=("Injection", "XSS", "Authentication/Authorization"),
        homepage="https://brakemanscanner.org/",
        integrated=True,
    ),
    "eslint-security": ToolCatalogEntry(
        name="eslint-security",
        display_name="ESLint Security",
        description="JavaScript/TypeScript lint rules for security anti-pattern detection.",
        category="Language-Specific SAST",
        command="eslint",
        target_modes=("codebase", "remote-codebase"),
        vulnerability_classes=("Unsafe Eval", "Command Injection", "XSS"),
        homepage="https://github.com/nodesecurity/eslint-plugin-security",
        integrated=True,
    ),
    "spotbugs": ToolCatalogEntry(
        name="spotbugs",
        display_name="SpotBugs",
        description="JVM bytecode analyzer with security detectors.",
        category="Language-Specific SAST",
        command="spotbugs",
        target_modes=("codebase", "remote-codebase"),
        vulnerability_classes=("Injection", "AuthZ flaws", "Crypto Misuse"),
        homepage="https://spotbugs.github.io/",
        integrated=True,
    ),
    "findsecbugs": ToolCatalogEntry(
        name="findsecbugs",
        display_name="FindSecBugs",
        description="SpotBugs plugin that adds security bug patterns for Java applications.",
        category="Language-Specific SAST",
        command="findsecbugs",
        target_modes=("codebase", "remote-codebase"),
        vulnerability_classes=("Injection", "XSS", "Deserialization"),
        homepage="https://find-sec-bugs.github.io/",
        integrated=True,
    ),
    "cppcheck": ToolCatalogEntry(
        name="cppcheck",
        display_name="Cppcheck",
        description="C/C++ static analyzer for memory safety and code defects.",
        category="Native Code SAST",
        command="cppcheck",
        target_modes=("codebase", "remote-codebase"),
        vulnerability_classes=("Memory Safety", "Race Conditions", "Undefined Behavior"),
        homepage="https://cppcheck.sourceforge.io/",
        integrated=True,
    ),
    "flawfinder": ToolCatalogEntry(
        name="flawfinder",
        display_name="Flawfinder",
        description="C/C++ risky function and coding flaw detector.",
        category="Native Code SAST",
        command="flawfinder",
        target_modes=("codebase", "remote-codebase"),
        vulnerability_classes=("Memory Safety", "Injection", "Unsafe APIs"),
        homepage="https://dwheeler.com/flawfinder/",
        integrated=True,
    ),
    "infer": ToolCatalogEntry(
        name="infer",
        display_name="Meta Infer",
        description="Interprocedural static analyzer for null dereference, race, and memory issues.",
        category="Advanced Static Analysis",
        command="infer",
        target_modes=("codebase", "remote-codebase"),
        vulnerability_classes=("Memory Safety", "Race Conditions", "Resource Leaks"),
        homepage="https://fbinfer.com/",
        integrated=True,
    ),
    "checkov": ToolCatalogEntry(
        name="checkov",
        display_name="Checkov",
        description="Infrastructure-as-Code scanner for cloud misconfigurations and policy violations.",
        category="IaC Security",
        command="checkov",
        target_modes=("codebase", "remote-codebase"),
        vulnerability_classes=("Misconfigurations", "Policy Violations"),
        homepage="https://www.checkov.io/",
        integrated=True,
    ),
    "tfsec": ToolCatalogEntry(
        name="tfsec",
        display_name="tfsec",
        description="Terraform security scanner for cloud IaC vulnerabilities.",
        category="IaC Security",
        command="tfsec",
        target_modes=("codebase", "remote-codebase"),
        vulnerability_classes=("Misconfigurations",),
        homepage="https://aquasecurity.github.io/tfsec/",
        integrated=True,
    ),
    "hadolint": ToolCatalogEntry(
        name="hadolint",
        display_name="Hadolint",
        description="Dockerfile linter with security and best-practice rules.",
        category="Container Hardening",
        command="hadolint",
        target_modes=("codebase", "remote-codebase"),
        vulnerability_classes=("Misconfigurations", "Supply Chain Risk"),
        homepage="https://github.com/hadolint/hadolint",
        integrated=True,
    ),
    "clair": ToolCatalogEntry(
        name="clair",
        display_name="Clair",
        description="Container vulnerability analysis platform for image contents.",
        category="Container Security",
        command="clairctl",
        target_modes=("codebase", "remote-codebase"),
        vulnerability_classes=("Dependency Vulnerabilities",),
        homepage="https://quay.github.io/clair/",
        integrated=True,
    ),
    "kube-bench": ToolCatalogEntry(
        name="kube-bench",
        display_name="kube-bench",
        description="Kubernetes CIS benchmark checker for cluster hardening posture.",
        category="Kubernetes Security",
        command="kube-bench",
        target_modes=("runtime",),
        vulnerability_classes=("Misconfigurations", "Hardening Gaps"),
        homepage="https://github.com/aquasecurity/kube-bench",
        integrated=True,
    ),
    "kube-hunter": ToolCatalogEntry(
        name="kube-hunter",
        display_name="kube-hunter",
        description="Kubernetes penetration-style scanner for exposed cluster weaknesses.",
        category="Kubernetes Security",
        command="kube-hunter",
        target_modes=("runtime",),
        vulnerability_classes=("Exposed Services", "Misconfigurations"),
        homepage="https://github.com/aquasecurity/kube-hunter",
        integrated=True,
    ),
    "wapiti": ToolCatalogEntry(
        name="wapiti",
        display_name="Wapiti",
        description="Web application black-box scanner for common vulnerabilities.",
        category="DAST / Web Security",
        command="wapiti",
        target_modes=("runtime",),
        vulnerability_classes=("Injection", "XSS", "File Inclusion", "Path Traversal"),
        homepage="https://wapiti-scanner.github.io/",
        integrated=True,
    ),
    "sqlmap": ToolCatalogEntry(
        name="sqlmap",
        display_name="sqlmap",
        description="Automated SQL injection testing and exploitation framework.",
        category="Specialized Injection Testing",
        command="sqlmap",
        target_modes=("runtime",),
        vulnerability_classes=("SQL Injection",),
        homepage="https://sqlmap.org/",
        integrated=True,
    ),
    "ffuf": ToolCatalogEntry(
        name="ffuf",
        display_name="ffuf",
        description="Fast web fuzzing tool for endpoint and parameter discovery.",
        category="Runtime Attack Surface Discovery",
        command="ffuf",
        target_modes=("runtime",),
        vulnerability_classes=("Hidden Endpoints", "Attack Surface Discovery"),
        homepage="https://github.com/ffuf/ffuf",
        integrated=True,
    ),
    "amass": ToolCatalogEntry(
        name="amass",
        display_name="OWASP Amass",
        description="Attack surface mapping and external asset discovery.",
        category="Runtime Attack Surface Discovery",
        command="amass",
        target_modes=("runtime",),
        vulnerability_classes=("Asset Exposure", "Shadow IT"),
        homepage="https://owasp.org/www-project-amass/",
        integrated=True,
    ),
}


DEFAULT_ACTIVE_CODEBASE_TOOLS = [
    "checkov",
    "gitleaks",
    "hadolint",
    "osv-scanner",
    "semgrep",
]
DEFAULT_ACTIVE_RUNTIME_TOOLS = [
    "runtime_http_probe",
    "amass",
    "ffuf",
    "kube-bench",
    "kube-hunter",
    "nikto",
    "nmap",
    "nuclei",
    "sqlmap",
    "wapiti",
    "zap-baseline",
]


def all_tool_names() -> list[str]:
    return sorted(TOOL_CATALOG.keys())


def get_tool_entry(tool_name: str) -> ToolCatalogEntry | None:
    return TOOL_CATALOG.get(tool_name.strip().lower())


def tool_names_for_target(target_mode: TargetMode) -> list[str]:
    normalized = target_mode.strip().lower()
    names = [name for name, item in TOOL_CATALOG.items() if normalized in item.target_modes]
    return sorted(names)


def integrated_tool_names_for_target(target_mode: TargetMode) -> list[str]:
    normalized = target_mode.strip().lower()
    names = [name for name, item in TOOL_CATALOG.items() if normalized in item.target_modes and item.integrated]
    return sorted(names)


def active_tools_for_target(target_mode: TargetMode) -> list[str]:
    normalized = target_mode.strip().lower()
    if normalized in {"codebase", "remote-codebase"}:
        return list(DEFAULT_ACTIVE_CODEBASE_TOOLS)
    if normalized == "runtime":
        return list(DEFAULT_ACTIVE_RUNTIME_TOOLS)
    return []
