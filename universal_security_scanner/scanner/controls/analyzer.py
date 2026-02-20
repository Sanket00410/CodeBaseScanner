from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from universal_security_scanner.models import SecurityControl


@dataclass(frozen=True, slots=True)
class ControlRule:
    control_id: str
    name: str
    category: str
    description: str
    standard_mappings: list[str]
    patterns: list[str]


CONTROL_RULES: list[ControlRule] = [
    ControlRule(
        control_id="CTRL-INPUT-VALIDATION",
        name="Input Validation Implemented",
        category="Application Input Security",
        description="Codebase contains explicit schema or input validation constructs.",
        standard_mappings=["OWASP ASVS V5", "ISO 27001 A.14", "NIST SSDF PW.5"],
        patterns=[
            r"\bpydantic\b",
            r"\bmarshmallow\b",
            r"\bjoi\b",
            r"\byup\b",
            r"\bexpress-validator\b",
            r"\bvalidate\s*\(",
            r"\bschema\s*=",
        ],
    ),
    ControlRule(
        control_id="CTRL-AUTHN",
        name="Authentication Controls Present",
        category="Identity and Access",
        description="Authentication middleware or token verification logic is present.",
        standard_mappings=["OWASP ASVS V2", "ISO 27001 A.9", "NIST SP 800-63"],
        patterns=[
            r"\bjwt\.verify\b",
            r"\b@login_required\b",
            r"\bOAuth2\b",
            r"\bpassport\.use\b",
            r"\bAuthenticationManager\b",
            r"\bspring-security\b",
        ],
    ),
    ControlRule(
        control_id="CTRL-AUTHZ",
        name="Authorization Controls Present",
        category="Identity and Access",
        description="Role/permission checks indicate access control enforcement.",
        standard_mappings=["OWASP ASVS V4", "ISO 27001 A.9", "NIST AC Controls"],
        patterns=[
            r"\b@PreAuthorize\b",
            r"\bhasRole\b",
            r"\brequiresRole\b",
            r"\bcanActivate\b",
            r"\bpermission\b",
            r"\bRBAC\b",
        ],
    ),
    ControlRule(
        control_id="CTRL-PASSWORD-HARDENING",
        name="Password Hardening",
        category="Cryptography and Credentials",
        description="Strong password hashing libraries are referenced.",
        standard_mappings=["OWASP ASVS V2", "NIST SP 800-63B", "ISO 27001 A.10"],
        patterns=[
            r"\bbcrypt\b",
            r"\bargon2\b",
            r"\bPBKDF2\b",
            r"\bscrypt\b",
            r"\bpasslib\b",
        ],
    ),
    ControlRule(
        control_id="CTRL-ENCRYPTION",
        name="Encryption Controls",
        category="Cryptography and Data Protection",
        description="Cryptographic APIs indicate encryption implementation.",
        standard_mappings=["OWASP ASVS V6", "ISO 27001 A.10", "NIST SC Controls"],
        patterns=[
            r"\bAES\b",
            r"\bFernet\b",
            r"\bcrypto\.(createCipheriv|subtle)\b",
            r"\bCipher\b",
            r"\bssl\.create_default_context\b",
        ],
    ),
    ControlRule(
        control_id="CTRL-TLS-TRANSPORT",
        name="TLS / Secure Transport",
        category="Network Security",
        description="TLS or HTTPS-only transport safeguards are present.",
        standard_mappings=["OWASP ASVS V9", "ISO 27001 A.13", "NIST SC-8"],
        patterns=[
            r"\bhttps://",
            r"\bTLS\b",
            r"\bssl\b",
            r"\bStrict-Transport-Security\b",
        ],
    ),
    ControlRule(
        control_id="CTRL-SECURE-HEADERS",
        name="Secure HTTP Headers",
        category="Web Security Hardening",
        description="Security headers/CSP/helmet usage is implemented.",
        standard_mappings=["OWASP ASVS V14", "ISO 27001 A.14", "NIST SI Controls"],
        patterns=[
            r"\bContent-Security-Policy\b",
            r"\bX-Frame-Options\b",
            r"\bX-Content-Type-Options\b",
            r"\bhelmet\b",
        ],
    ),
    ControlRule(
        control_id="CTRL-CSRF",
        name="CSRF Protection",
        category="Web Security Hardening",
        description="Framework-level anti-CSRF mechanisms are enabled.",
        standard_mappings=["OWASP ASVS V4", "OWASP CSRF Cheat Sheet", "ISO 27001 A.14"],
        patterns=[
            r"\bcsrf\b",
            r"\bCSRFProtect\b",
            r"\bSameSite\b",
        ],
    ),
    ControlRule(
        control_id="CTRL-LOGGING-AUDIT",
        name="Security Logging and Auditing",
        category="Detection and Monitoring",
        description="Audit and security logging behavior is present in codebase.",
        standard_mappings=["OWASP ASVS V10", "ISO 27001 A.12.4", "NIST AU Controls"],
        patterns=[
            r"\baudit\b",
            r"\bsecurity[_-]?log\b",
            r"\bSIEM\b",
            r"\bstructured logging\b",
        ],
    ),
    ControlRule(
        control_id="CTRL-SECRET-MANAGEMENT",
        name="Secret Management Usage",
        category="Cryptography and Credentials",
        description="Secret manager or vault integrations are referenced.",
        standard_mappings=["OWASP Secrets Management", "ISO 27001 A.9", "NIST IA Controls"],
        patterns=[
            r"\bVault\b",
            r"\bAWS Secrets Manager\b",
            r"\bKeyVault\b",
            r"\bSecretManager\b",
            r"\benv\[\"[A-Z0-9_]+\"\]",
        ],
    ),
]


class ExistingSecurityMeasuresAnalyzer:
    def __init__(self) -> None:
        self._compiled = {
            rule.control_id: [re.compile(pattern, re.IGNORECASE) for pattern in rule.patterns]
            for rule in CONTROL_RULES
        }
        self._evidence: dict[str, list[dict[str, str | int]]] = {rule.control_id: [] for rule in CONTROL_RULES}

    def observe_file(self, file_path: Path, content: str) -> None:
        lines = content.splitlines()
        for rule in CONTROL_RULES:
            if len(self._evidence[rule.control_id]) >= 12:
                continue
            patterns = self._compiled[rule.control_id]
            for line_number, line in enumerate(lines, start=1):
                if any(regex.search(line) for regex in patterns):
                    self._evidence[rule.control_id].append(
                        {
                            "file_path": str(file_path),
                            "line_number": line_number,
                            "snippet": line.strip()[:220],
                        }
                    )
                    break

    def finalize(self, total_files: int) -> list[SecurityControl]:
        controls: list[SecurityControl] = []

        for rule in CONTROL_RULES:
            evidence = self._evidence.get(rule.control_id, [])
            if not evidence:
                continue

            affected_files = len({str(item["file_path"]) for item in evidence})
            ratio = 0.0 if total_files <= 0 else affected_files / total_files

            if ratio >= 0.25:
                coverage = "High"
            elif ratio >= 0.08:
                coverage = "Medium"
            else:
                coverage = "Low"

            controls.append(
                SecurityControl(
                    control_id=rule.control_id,
                    name=rule.name,
                    category=rule.category,
                    description=rule.description,
                    status="Implemented",
                    coverage_level=coverage,
                    standard_mappings=list(rule.standard_mappings),
                    evidence=evidence,
                )
            )

        controls.sort(key=lambda item: (item.category, item.name))
        return controls
