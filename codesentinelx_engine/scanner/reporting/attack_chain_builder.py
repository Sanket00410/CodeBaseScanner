from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .report_models import (
    AttackChain,
    AttackChainStep,
    ProfessionalFinding,
    Severity,
)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


_SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}

_VULN_TO_KILL_CHAIN_PHASE: dict[str, tuple[str, str]] = {
    # vuln_type_keyword -> (kill_chain_phase, mitre_tactic)
    "sql": ("Exploitation", "TA0001 - Initial Access"),
    "command": ("Exploitation", "TA0002 - Execution"),
    "xss": ("Delivery", "TA0001 - Initial Access"),
    "ssrf": ("Exploitation", "TA0001 - Initial Access"),
    "path traversal": ("Exploitation", "TA0001 - Initial Access"),
    "directory": ("Exploitation", "TA0001 - Initial Access"),
    "secret": ("Reconnaissance", "TA0009 - Collection"),
    "credential": ("Reconnaissance", "TA0009 - Collection"),
    "password": ("Reconnaissance", "TA0009 - Collection"),
    "auth": ("Exploitation", "TA0003 - Persistence"),
    "session": ("Exploitation", "TA0003 - Persistence"),
    "token": ("Exploitation", "TA0003 - Persistence"),
    "cookie": ("Exploitation", "TA0006 - Credential Access"),
    "jwt": ("Exploitation", "TA0006 - Credential Access"),
    "csrf": ("Delivery", "TA0004 - Privilege Escalation"),
    "open redirect": ("Delivery", "TA0001 - Initial Access"),
    "crypto": ("Exploitation", "TA0005 - Defense Evasion"),
    "ssl": ("Exploitation", "TA0005 - Defense Evasion"),
    "tls": ("Exploitation", "TA0005 - Defense Evasion"),
    "insecure": ("Exploitation", "TA0005 - Defense Evasion"),
}

_KILL_CHAIN_PHASES = ["Reconnaissance", "Weaponization", "Delivery", "Exploitation", "Installation", "Command & Control", "Actions on Objectives"]


def _get_attack_phase_and_tactic(vulnerability_type: str) -> tuple[str, str]:
    lower = vulnerability_type.lower()
    for keyword, (phase, tactic) in _VULN_TO_KILL_CHAIN_PHASE.items():
        if keyword in lower:
            return (phase, tactic)
    return ("Exploitation", "TA0001 - Initial Access")


def _get_kill_chain_phases_from_steps(steps: list[AttackChainStep]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for step in steps:
        phase = step.attack_phase or "Exploitation"
        if phase not in seen:
            seen.add(phase)
            ordered.append(phase)
    # Reorder based on kill chain ordering
    ordered.sort(key=lambda p: _KILL_CHAIN_PHASES.index(p) if p in _KILL_CHAIN_PHASES else 99)
    return ordered


@dataclass(slots=True)
class ChainCandidate:
    title: str
    description: str
    severity: Severity
    finding_uids: list[str] = field(default_factory=list)
    mitre_ids: list[str] = field(default_factory=list)
    final_impact: str = ""
    mitigation_summary: str = ""


@dataclass(slots=True)
class AttackChainBuilderConfig:
    max_chain_length: int = 6
    min_chain_length: int = 2
    enable_heuristic_chains: bool = True
    enable_dependency_chains: bool = True
    enable_auth_bypass_chains: bool = True


_KNOWN_CHAIN_PATTERNS: list[ChainCandidate] = [
    ChainCandidate(
        title="Credential Theft → Privilege Escalation",
        description=(
            "Attacker exploits hardcoded secrets or weak credentials to gain initial access, "
            "then leverages missing authorization checks to escalate to admin."
        ),
        severity=Severity.HIGH,
        mitre_ids=["T1078", "T1059", "T1068"],
        final_impact="Full administrative access to the application.",
        mitigation_summary=(
            "Rotate all exposed credentials. Enforce MFA. Implement role-based access "
            "control checks at every privileged endpoint."
        ),
    ),
    ChainCandidate(
        title="Injection → Data Exfiltration",
        description=(
            "Attacker injects malicious payloads via unsanitized inputs (SQL injection, command "
            "injection, or template injection), then extracts sensitive data or pivots to the "
            "underlying database or OS."
        ),
        severity=Severity.CRITICAL,
        mitre_ids=["T1190", "T1005", "T1041"],
        final_impact="Full database dump or remote code execution.",
        mitigation_summary=(
            "Use parameterized queries. Validate and sanitize all user inputs. Apply least "
            "privilege to database accounts."
        ),
    ),
    ChainCandidate(
        title="SSRF → Internal Network Pivoting",
        description=(
            "Attacker exploits SSRF to reach internal services, metadata endpoints, or "
            "admin panels not exposed to the public internet."
        ),
        severity=Severity.HIGH,
        mitre_ids=["T1190", "T1552", "T1046"],
        final_impact="Access to cloud metadata, internal APIs, or admin panels.",
        mitigation_summary=(
            "Restrict outbound requests to a whitelist of allowed hosts. Disable access to "
            "link-local and internal IP ranges."
        ),
    ),
    ChainCandidate(
        title="XSS → Session Hijacking → Account Takeover",
        description=(
            "Attacker injects cross-site scripting payload that steals session cookies or "
            "tokens, allowing full account impersonation."
        ),
        severity=Severity.HIGH,
        mitre_ids=["T1189", "T1539", "T1550"],
        final_impact="Full account takeover via stolen session tokens.",
        mitigation_summary=(
            "Implement Content Security Policy. Use HttpOnly and Secure cookie flags. "
            "Validate and encode all output."
        ),
    ),
    ChainCandidate(
        title="Path Traversal → Configuration Leak",
        description=(
            "Attacker uses directory traversal to read sensitive configuration files, "
            "environment variables, or private keys."
        ),
        severity=Severity.CRITICAL,
        mitre_ids=["T1190", "T1552", "T1555"],
        final_impact="Exposure of credentials, API keys, or signing secrets.",
        mitigation_summary=(
            "Validate and canonicalize file paths. Apply chroot or sandbox restrictions. "
            "Never serve configuration files via the web server."
        ),
    ),
]


def _severity_rank(sev: Severity | str) -> int:
    if isinstance(sev, Severity):
        return _SEVERITY_ORDER.get(sev, 5)
    sev_str = str(sev).lower()
    mapping = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return mapping.get(sev_str, 5)


class AttackChainBuilder:
    def __init__(self, config: AttackChainBuilderConfig | None = None) -> None:
        self._config = config or AttackChainBuilderConfig()

    def build_chains(
        self,
        findings: list[ProfessionalFinding],
        *,
        known_patterns: list[ChainCandidate] | None = None,
    ) -> list[AttackChain]:
        patterns = known_patterns or _KNOWN_CHAIN_PATTERNS
        chains: list[AttackChain] = []
        for pattern in patterns:
            matched_uids = self._match_pattern_to_findings(pattern, findings)
            if len(matched_uids) >= self._config.min_chain_length:
                chains.append(
                    self._build_chain_from_pattern(pattern, matched_uids, findings)
                )
        if self._config.enable_heuristic_chains:
            chains.extend(self._build_heuristic_chains(findings))
        chains.sort(key=lambda c: _severity_rank(c.severity))
        return chains[: self._config.max_chain_length]

    def _match_pattern_to_findings(
        self,
        pattern: ChainCandidate,
        findings: list[ProfessionalFinding],
    ) -> list[str]:
        matched: list[str] = []
        for f in findings:
            if self._finding_matches_pattern(f, pattern):
                matched.append(f.finding_uid)
        return matched

    def _finding_matches_pattern(
        self,
        finding: ProfessionalFinding,
        pattern: ChainCandidate,
    ) -> bool:
        vuln_lower = finding.title.lower()
        if "injection" in pattern.title.lower() and any(
            kw in vuln_lower
            for kw in ["sql", "command", "template", "code injection"]
        ):
            return True
        if "xss" in pattern.title.lower() and "xss" in vuln_lower:
            return True
        if "ssrf" in pattern.title.lower() and "ssrf" in vuln_lower:
            return True
        if "path traversal" in pattern.title.lower() and (
            "path traversal" in vuln_lower or "directory" in vuln_lower
        ):
            return True
        if "credential" in pattern.title.lower() and any(
            kw in vuln_lower
            for kw in ["secret", "credential", "hardcoded", "password"]
        ):
            return True
        if "auth" in pattern.title.lower() and any(
            kw in vuln_lower
            for kw in ["auth", "authorization", "access control", "privilege"]
        ):
            return True
        for mitre_id in pattern.mitre_ids:
            if any(
                mitre_id in ref.category_id
                for ref in finding.references
                if "MITRE" in (ref.framework or "").upper()
                or "MITRE" in (ref.category_id or "").upper()
            ):
                return True
        return False

    def _build_chain_from_pattern(
        self,
        pattern: ChainCandidate,
        finding_uids: list[str],
        findings: list[ProfessionalFinding],
    ) -> AttackChain:
        uid_to_finding = {f.finding_uid: f for f in findings}
        steps: list[AttackChainStep] = []
        for i, uid in enumerate(finding_uids[: self._config.max_chain_length]):
            f = uid_to_finding.get(uid)
            if not f:
                continue
            phase, tactic = _get_attack_phase_and_tactic(f.title)
            steps.append(
                AttackChainStep(
                    step_number=i + 1,
                    finding_uid=uid,
                    title=f.title,
                    severity=f.severity,
                    description=f.description,
                    entry_point=f"{f.file_path}:{f.line_number}",
                    technique=_technique_for_vuln(f.title),
                    mitre_id=_mitre_id_for_vuln(f.title),
                    impact=f.risk_explanation or f.description,
                    next_step_uid=finding_uids[i + 1] if i + 1 < len(finding_uids) else "",
                    attack_phase=phase,
                    mitre_tactic=tactic,
                )
            )
        chain_id = f"CHAIN-{_hash_short(pattern.title)}"
        kill_phases = _get_kill_chain_phases_from_steps(steps)
        return AttackChain(
            chain_id=chain_id,
            title=pattern.title,
            description=pattern.description,
            severity=pattern.severity.value if hasattr(pattern.severity, "value") else str(pattern.severity),
            steps=steps,
            final_impact=pattern.final_impact,
            mitigation_summary=pattern.mitigation_summary,
            kill_chain_phases=kill_phases,
            created_at=_now_iso(),
        )

    def _build_heuristic_chains(
        self,
        findings: list[ProfessionalFinding],
    ) -> list[AttackChain]:
        chains: list[AttackChain] = []
        if not self._config.enable_auth_bypass_chains:
            return chains
        auth_findings = [
            f
            for f in findings
            if any(
                kw in f.title.lower()
                for kw in ["auth", "session", "token", "cookie", "jwt"]
            )
        ]
        injection_findings = [
            f
            for f in findings
            if any(
                kw in f.title.lower()
                for kw in ["injection", "xss", "ssrf", "traversal"]
            )
        ]
        if auth_findings and injection_findings:
            combined = (auth_findings + injection_findings)[
                : self._config.max_chain_length
            ]
            steps: list[AttackChainStep] = []
            for i, f in enumerate(combined):
                phase, tactic = _get_attack_phase_and_tactic(f.title)
                steps.append(
                    AttackChainStep(
                        step_number=i + 1,
                        finding_uid=f.finding_uid,
                        title=f.title,
                        severity=f.severity,
                        description=f.description,
                        entry_point=f"{f.file_path}:{f.line_number}",
                        technique=_technique_for_vuln(f.title),
                        mitre_id=_mitre_id_for_vuln(f.title),
                        impact=f.risk_explanation or f.description,
                        next_step_uid=combined[i + 1].finding_uid
                        if i + 1 < len(combined)
                        else "",
                        attack_phase=phase,
                        mitre_tactic=tactic,
                    )
                )
            chain_id = f"CHAIN-HEUR-{_hash_short('auth-injection')}"
            kill_phases = _get_kill_chain_phases_from_steps(steps)
            chains.append(
                AttackChain(
                    chain_id=chain_id,
                    title="Authentication Weakness + Injection Attack",
                    description=(
                        "Combination of authentication weaknesses and injection "
                        "vulnerabilities that together enable full compromise."
                    ),
                    severity="High",
                    steps=steps,
                    final_impact="Full application compromise via authentication bypass and injection.",
                    mitigation_summary="Fix both authentication and injection issues in priority order.",
                    kill_chain_phases=kill_phases,
                    created_at=_now_iso(),
                )
            )
        return chains


def _technique_for_vuln(vulnerability_type: str) -> str:
    lower = vulnerability_type.lower()
    if "sql" in lower:
        return "T1190 - Exploit Public-Facing Application (SQL Injection)"
    if "command" in lower:
        return "T1059 - Command and Scripting Interpreter"
    if "xss" in lower:
        return "T1189 - Drive-by Compromise"
    if "ssrf" in lower:
        return "T1190 - Exploit Public-Facing Application (SSRF)"
    if "path traversal" in lower:
        return "T1190 - Exploit Public-Facing Application (Path Traversal)"
    if "secret" in lower or "credential" in lower:
        return "T1552 - Credentials in Files"
    if "auth" in lower or "session" in lower:
        return "T1078 - Valid Accounts"
    return "T1190 - Exploit Public-Facing Application"


def _mitre_id_for_vuln(vulnerability_type: str) -> str:
    lower = vulnerability_type.lower()
    if "sql" in lower:
        return "CAPEC-66"
    if "command" in lower:
        return "CAPEC-88"
    if "xss" in lower:
        return "CAPEC-86"
    if "ssrf" in lower:
        return "CAPEC-916"
    if "path traversal" in lower:
        return "CAPEC-126"
    if "secret" in lower or "credential" in lower:
        return "CAPEC-212"
    if "auth" in lower or "session" in lower:
        return "CAPEC-114"
    return "CAPEC-200"


def _hash_short(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:8].upper()
