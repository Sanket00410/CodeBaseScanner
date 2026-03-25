from __future__ import annotations

from pathlib import Path

from universal_security_scanner.config import ScannerConfig
from universal_security_scanner.models import Finding
from universal_security_scanner.scanner.native_rules import iter_native_flow_rules
from universal_security_scanner.scanner.source_analysis import analyze_family


class NativeCodeScanner:
    """Phase 1 native code-analysis engine.

    This scanner is additive: it reuses the first-party parser/dataflow engine and
    emits normalized findings without removing the existing plugin/tool pipeline.
    """

    def __init__(self, config: ScannerConfig) -> None:
        self.config = config
        self.enabled = bool(config.use_native_code_analysis)
        self.languages = {item.strip().lower() for item in config.native_analysis_languages if item.strip()}
        self.families = {item.strip().lower() for item in config.native_analysis_families if item.strip()}
        self.max_findings_per_file = max(1, config.native_max_findings_per_file)

    def supports(self, file_path: Path) -> bool:
        if not self.enabled:
            return False
        return bool(iter_native_flow_rules(languages=self.languages, families=self.families, file_suffix=file_path.suffix))

    def scan_file(self, file_path: Path, content: str) -> list[Finding]:
        if not self.supports(file_path):
            return []

        findings: list[Finding] = []
        for rule in iter_native_flow_rules(
            languages=self.languages,
            families=self.families,
            file_suffix=file_path.suffix,
        ):
            matches = analyze_family(content, file_path.suffix, rule.family)
            for match in matches:
                findings.append(
                    rule.build_finding(
                        file_path=file_path,
                        line_number=match.line_number,
                        evidence=match.evidence_summary(),
                    )
                )
                if len(findings) >= self.max_findings_per_file:
                    return findings
        return findings
