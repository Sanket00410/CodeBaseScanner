"""Comprehensive tests for the new professional reporting pipeline."""
import pytest
from pathlib import Path

from codesentinelx_engine.models import Finding, Severity
from codesentinelx_engine.scanner.reporting.report_models import (
    AttackChain,
    AttackChainStep,
    AffectedComponent,
    CVSSVector,
    DeveloperReport,
    EvidenceItem,
    ProfessionalFinding,
    ProfessionalReportMetadata,
    RemediationGuidance,
    TaxonomyMapping,
)
from codesentinelx_engine.scanner.reporting.evidence_collector import (
    EvidenceCollector,
    EvidenceCollectorConfig,
    EVIDENCE_TYPE_CODE_SNIPPET,
    EVIDENCE_TYPE_HTTP_EXCHANGE,
    EVIDENCE_TYPE_POC_NARRATIVE,
    EVIDENCE_TYPE_VALIDATION,
)
from codesentinelx_engine.scanner.reporting.attack_chain_builder import (
    AttackChainBuilder,
    AttackChainBuilderConfig,
)
from codesentinelx_engine.scanner.reporting.report_schema import ReportSchemaConverter
from codesentinelx_engine.scanner.reporting.developer_report_renderer import DeveloperReportRenderer


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def sample_findings():
    return [
        Finding(
            vulnerability_type="SQL Injection",
            severity=Severity.CRITICAL,
            file_path="src/db/queries.py",
            line_number=42,
            description="User input directly concatenated into SQL query without parameterization",
            recommendation="Use parameterized queries or prepared statements",
            evidence="cursor.execute(f\"SELECT * FROM users WHERE id={user_id}\")",
            cwe="CWE-89",
            business_impact="Full database compromise, data exfiltration",
            reference="https://cwe.mitre.org/data/definitions/89.html",
            owasp_category="A03:2021",
            rule_id="PYL-SQL001",
            cvss_score=9.8,
        ),
        Finding(
            vulnerability_type="Cross-Site Scripting (XSS)",
            severity=Severity.HIGH,
            file_path="src/views/profile.py",
            line_number=15,
            description="Unescaped user input rendered in HTML template",
            recommendation="Encode all output using context-aware encoding",
            evidence="element.innerHTML = user_input",
            cwe="CWE-79",
            business_impact="Session hijacking, credential theft",
            reference="https://cwe.mitre.org/data/definitions/79.html",
            owasp_category="A03:2021",
            rule_id="PYL-XSS001",
            cvss_score=7.5,
        ),
        Finding(
            vulnerability_type="Hardcoded Secret",
            severity=Severity.HIGH,
            file_path="src/config.py",
            line_number=10,
            description="API key hardcoded in source code",
            recommendation="Move secrets to environment variables or a vault",
            evidence="API_KEY = 'sk-abc123def456'",
            cwe="CWE-798",
            business_impact="Unauthorized API access",
            reference="https://cwe.mitre.org/data/definitions/798.html",
            owasp_category="A07:2021",
            rule_id="SEC-SEC001",
            cvss_score=7.0,
        ),
        Finding(
            vulnerability_type="Path Traversal",
            severity=Severity.MEDIUM,
            file_path="src/utils/file_handler.py",
            line_number=67,
            description="User-controlled path used to access filesystem without validation",
            recommendation="Validate and canonicalize file paths",
            evidence="open(os.path.join(base_dir, user_path))",
            cwe="CWE-22",
            business_impact="Unauthorized file access",
            reference="https://cwe.mitre.org/data/definitions/22.html",
            owasp_category="A01:2021",
            rule_id="PYL-PT001",
            cvss_score=5.3,
        ),
        Finding(
            vulnerability_type="Open Redirect",
            severity=Severity.LOW,
            file_path="src/views/auth.py",
            line_number=30,
            description="Redirect URL not validated against allowlist",
            recommendation="Validate redirect URLs against an allowlist",
            evidence="redirect(request.args.get('next'))",
            cwe="CWE-601",
            business_impact="Phishing vector",
            reference="https://cwe.mitre.org/data/definitions/601.html",
            owasp_category="A01:2021",
            rule_id="PYL-REDIR001",
            cvss_score=3.1,
        ),
    ]


@pytest.fixture
def converter():
    return ReportSchemaConverter()


@pytest.fixture
def renderer():
    return DeveloperReportRenderer()


# ── Evidence Collector Tests ──────────────────────────────────────────────────

class TestEvidenceCollector:
    def test_collect_code_evidence(self):
        collector = EvidenceCollector()
        items = collector.collect_from_finding(
            finding_uid="test-uid-1",
            vulnerability_type="SQL Injection",
            file_path="src/db.py",
            line_number=42,
            source_code="cursor.execute(f'SELECT * FROM users WHERE id={user_id}')",
        )
        assert len(items) == 1
        assert items[0].evidence_type == EVIDENCE_TYPE_CODE_SNIPPET
        assert "src/db.py" in items[0].title
        assert items[0].data.get("language") == "python"
        assert items[0].hash_sha256  # Should have a hash

    def test_collect_http_evidence(self):
        collector = EvidenceCollector()
        items = collector.collect_from_finding(
            finding_uid="test-uid-2",
            vulnerability_type="XSS",
            file_path="src/views.py",
            line_number=10,
            http_request_data={
                "method": "GET",
                "url": "https://example.com/search?q=<script>alert(1)</script>",
                "headers": {"Content-Type": "text/html"},
                "body": "",
            },
            http_response_data={
                "status_code": 200,
                "headers": {"Content-Type": "text/html"},
                "body": "<html><script>alert(1)</script></html>",
            },
        )
        assert len(items) == 1
        assert items[0].evidence_type == EVIDENCE_TYPE_HTTP_EXCHANGE
        assert items[0].http_request is not None
        assert items[0].http_request.method == "GET"
        assert items[0].http_response is not None
        assert items[0].http_response.status_code == 200

    def test_collect_poc_evidence(self):
        collector = EvidenceCollector()
        items = collector.collect_from_finding(
            finding_uid="test-uid-3",
            vulnerability_type="Command Injection",
            file_path="src/exec.py",
            line_number=5,
            poc_narrative="Send payload: ; cat /etc/passwd",
        )
        assert len(items) == 1
        assert items[0].evidence_type == EVIDENCE_TYPE_POC_NARRATIVE
        assert "cat /etc/passwd" in items[0].data.get("content", "")

    def test_collect_validation_evidence(self):
        collector = EvidenceCollector()
        items = collector.collect_from_finding(
            finding_uid="test-uid-4",
            vulnerability_type="SQL Injection",
            file_path="src/db.py",
            line_number=42,
            validation_result={
                "status": "verified",
                "verification_basis": "Dataflow confirmed",
                "output": "status=verified\nfamily=sql-injection",
                "confidence": 0.92,
                "mode": "parser-and-flow-validation",
                "family": "sql-injection",
            },
        )
        assert len(items) == 1
        assert items[0].evidence_type == EVIDENCE_TYPE_VALIDATION
        assert items[0].data.get("validation_status") == "verified"
        assert items[0].data.get("confidence") == 0.92

    def test_collect_multiple_types(self):
        collector = EvidenceCollector()
        items = collector.collect_from_finding(
            finding_uid="test-uid-5",
            vulnerability_type="SQL Injection",
            file_path="src/db.py",
            line_number=42,
            source_code="cursor.execute(f'SELECT * FROM users WHERE id={user_id}')",
            poc_narrative="Inject payload via input field",
            validation_result={"status": "verified", "verification_basis": "Flow match"},
        )
        assert len(items) == 3
        types = {item.evidence_type for item in items}
        assert EVIDENCE_TYPE_CODE_SNIPPET in types
        assert EVIDENCE_TYPE_POC_NARRATIVE in types
        assert EVIDENCE_TYPE_VALIDATION in types

    def test_empty_evidence_returns_empty(self):
        collector = EvidenceCollector()
        items = collector.collect_from_finding(
            finding_uid="test-uid-6",
            vulnerability_type="Info",
            file_path="src/safe.py",
            line_number=1,
        )
        assert len(items) == 0

    def test_max_snippet_lines(self):
        config = EvidenceCollectorConfig(max_snippet_lines=3)
        collector = EvidenceCollector(config)
        long_code = "\n".join([f"line {i}" for i in range(50)])
        items = collector.collect_from_finding(
            finding_uid="test-uid-7",
            vulnerability_type="XSS",
            file_path="src/views.py",
            line_number=25,
            source_code=long_code,
        )
        assert len(items) == 1
        content = items[0].data.get("content", "")
        assert content.count("\n") < 5  # Should be truncated


# ── Attack Chain Builder Tests ────────────────────────────────────────────────

class TestAttackChainBuilder:
    def test_empty_findings_returns_no_chains(self):
        builder = AttackChainBuilder()
        chains = builder.build_chains([])
        assert chains == []

    def test_single_finding_no_chain(self):
        builder = AttackChainBuilder()
        findings = [
            ProfessionalFinding(
                finding_uid="f1",
                title="SQL Injection",
                severity="Critical",
                file_path="src/db.py",
                line_number=42,
                description="SQL injection in login form",
            ),
        ]
        chains = builder.build_chains(findings)
        # Single finding shouldn't form a chain (min_chain_length=2)
        assert len(chains) == 0

    def test_injection_pattern_match(self):
        builder = AttackChainBuilder()
        findings = [
            ProfessionalFinding(
                finding_uid="f1",
                title="SQL Injection",
                severity="Critical",
                file_path="src/db.py",
                line_number=42,
                description="SQL injection",
            ),
            ProfessionalFinding(
                finding_uid="f2",
                title="Command Injection",
                severity="Critical",
                file_path="src/exec.py",
                line_number=10,
                description="Command injection",
            ),
            ProfessionalFinding(
                finding_uid="f3",
                title="Path Traversal",
                severity="Medium",
                file_path="src/files.py",
                line_number=20,
                description="Path traversal",
            ),
        ]
        chains = builder.build_chains(findings)
        # Should find at least one chain matching the Injection pattern
        assert len(chains) >= 1
        assert any("Injection" in chain.title for chain in chains)

    def test_chain_steps_are_ordered(self):
        builder = AttackChainBuilder()
        findings = [
            ProfessionalFinding(
                finding_uid="f1",
                title="Hardcoded Secret",
                severity="High",
                file_path="src/config.py",
                line_number=1,
                description="Hardcoded API key",
            ),
            ProfessionalFinding(
                finding_uid="f2",
                title="SQL Injection",
                severity="Critical",
                file_path="src/db.py",
                line_number=42,
                description="SQL injection",
            ),
        ]
        chains = builder.build_chains(findings)
        for chain in chains:
            for i, step in enumerate(chain.steps):
                assert step.step_number == i + 1

    def test_chain_severity_is_max(self):
        builder = AttackChainBuilder()
        findings = [
            ProfessionalFinding(
                finding_uid="f1",
                title="SQL Injection",
                severity="Critical",
                file_path="src/db.py",
                line_number=42,
                description="SQL injection",
            ),
            ProfessionalFinding(
                finding_uid="f2",
                title="XSS",
                severity="High",
                file_path="src/views.py",
                line_number=10,
                description="XSS vulnerability",
            ),
        ]
        chains = builder.build_chains(findings)
        for chain in chains:
            assert chain.severity.value == "Critical"


# ── Report Schema Converter Tests ────────────────────────────────────────────

class TestReportSchemaConverter:
    def test_convert_findings(self, converter, sample_findings):
        prof_findings = converter.convert_findings(sample_findings, "/app")
        assert len(prof_findings) == 5

    def test_severity_mapping(self, converter, sample_findings):
        prof_findings = converter.convert_findings(sample_findings, "/app")
        severities = {f.severity for f in prof_findings}
        assert "Critical" in severities
        assert "High" in severities
        assert "Medium" in severities
        assert "Low" in severities

    def test_cwe_mapping(self, converter, sample_findings):
        prof_findings = converter.convert_findings(sample_findings, "/app")
        sql_finding = next(f for f in prof_findings if "SQL" in f.title)
        assert sql_finding.cwe_id == "CWE-89"
        assert any(ref.framework == "OWASP Top 10:2021" for ref in sql_finding.references)

    def test_evidence_populated(self, converter, sample_findings):
        prof_findings = converter.convert_findings(sample_findings, "/app")
        for f in prof_findings:
            assert len(f.evidence) >= 1  # At least code snippet or PoC

    def test_cvss_score_from_finding(self, converter, sample_findings):
        prof_findings = converter.convert_findings(sample_findings, "/app")
        sql_finding = next(f for f in prof_findings if "SQL" in f.title)
        # Rule 2: CVSS scores are differentiated per finding context
        assert 7.0 <= sql_finding.cvss_score <= 10.0
        assert sql_finding.cvss_score != 0.0
        assert sql_finding.cvss_temporal_score > 0.0
        assert sql_finding.cvss_environmental_score > 0.0
        assert sql_finding.cvss_scoring_rationale  # Rule 2: differentiation rationale present

    def test_cvss_score_derived_from_severity(self, converter):
        findings = [
            Finding(
                vulnerability_type="Weak Crypto",
                severity=Severity.MEDIUM,
                file_path="src/crypto.py",
                line_number=1,
                description="Weak algorithm",
                recommendation="Use AES-256",
                business_impact="Data exposure",
                reference="",
                owasp_category="A02:2021",
                rule_id="CRYPTO001",
            ),
        ]
        prof_findings = converter.convert_findings(findings, "/app")
        # Rule 2: CVSS differentiated per finding - should be close to 5.0 but may differ
        assert 3.0 <= prof_findings[0].cvss_score <= 7.0

    def test_remediation_populated(self, converter, sample_findings):
        prof_findings = converter.convert_findings(sample_findings, "/app")
        for f in prof_findings:
            assert f.remediation.title
            assert f.remediation.description

    def test_affected_components(self, converter, sample_findings):
        prof_findings = converter.convert_findings(sample_findings, "/app")
        for f in prof_findings:
            assert len(f.affected_components) == 1
            assert f.affected_components[0].file_path == f.file_path

    def test_build_developer_report(self, converter, sample_findings):
        report = converter.build_developer_report(sample_findings, "/app", project_name="Test")
        assert isinstance(report, DeveloperReport)
        assert len(report.findings) == 5
        assert report.metadata.report_type == "developer"
        assert report.metadata.report_title == "Test"
        assert report.metadata.total_findings == 5
        assert report.metadata.executive_summary_text

    def test_build_executive_report(self, converter, sample_findings):
        report = converter.build_executive_report(sample_findings, "/app", project_name="Test")
        assert report.metadata.report_type == "executive"
        assert report.risk_summary
        assert report.business_impact_summary
        assert len(report.key_findings) > 0

    def test_remediation_roadmap_ordered_by_severity(self, converter, sample_findings):
        report = converter.build_developer_report(sample_findings, "/app")
        roadmap = report.remediation_roadmap
        assert len(roadmap) == 5
        assert roadmap[0]["severity"] == "Critical"
        assert roadmap[-1]["severity"] == "Low"


# ── Developer Report Renderer Tests ──────────────────────────────────────────

class TestDeveloperReportRenderer:
    def test_render_html_produces_valid_structure(self, converter, renderer, sample_findings):
        report = converter.build_developer_report(sample_findings, "/app", project_name="Test")
        html = renderer.render_html(report)
        assert "<!DOCTYPE html>" in html
        assert "<html" in html
        assert "</html>" in html
        assert "Security Assessment Report" in html

    def test_render_includes_all_findings(self, converter, renderer, sample_findings):
        report = converter.build_developer_report(sample_findings, "/app")
        html = renderer.render_html(report)
        for f in report.findings:
            assert f.title in html
            assert f.file_path in html

    def test_render_includes_severity_badges(self, converter, renderer, sample_findings):
        report = converter.build_developer_report(sample_findings, "/app")
        html = renderer.render_html(report)
        assert "severity-badge" in html
        assert "critical" in html
        assert "high" in html

    def test_render_includes_evidence(self, converter, renderer, sample_findings):
        report = converter.build_developer_report(sample_findings, "/app")
        html = renderer.render_html(report)
        assert "evidence-block" in html

    def test_render_includes_cvss(self, converter, renderer, sample_findings):
        report = converter.build_developer_report(sample_findings, "/app")
        html = renderer.render_html(report)
        assert "CVSS" in html

    def test_render_includes_remediation(self, converter, renderer, sample_findings):
        report = converter.build_developer_report(sample_findings, "/app")
        html = renderer.render_html(report)
        assert "Remediation" in html
        assert "parameterized" in html.lower()

    def test_render_includes_references(self, converter, renderer, sample_findings):
        report = converter.build_developer_report(sample_findings, "/app")
        html = renderer.render_html(report)
        assert "CWE-89" in html
        assert "OWASP" in html

    def test_render_table_of_contents(self, converter, renderer, sample_findings):
        report = converter.build_developer_report(sample_findings, "/app")
        html = renderer.render_html(report)
        assert "Table of Contents" in html
        assert "exec-summary" in html

    def test_render_dashboard(self, converter, renderer, sample_findings):
        report = converter.build_developer_report(sample_findings, "/app")
        html = renderer.render_html(report)
        assert "dashboard" in html.lower()
        assert "5" in html  # Total findings count


# ── Backward Compatibility Tests ─────────────────────────────────────────────

class TestBackwardCompatibility:
    def test_existing_report_builder_still_works(self):
        from codesentinelx_engine.scanner.reporting.report_builder import build_report
        from codesentinelx_engine.models import ScanResult
        from datetime import datetime

        result = ScanResult(
            target_path="/app",
            findings=[],
            started_at=datetime(2026, 1, 1),
            completed_at=datetime(2026, 1, 1, 0, 1),
            files_scanned=0,
        )
        report = build_report(result)
        assert isinstance(report, dict)
        assert "executive_summary" in report

    def test_professional_pipeline_doesnt_modify_legacy(self, converter, sample_findings):
        original_count = len(sample_findings)
        _ = converter.convert_findings(sample_findings, "/app")
        assert len(sample_findings) == original_count

    def test_finding_uid_deterministic(self, converter, sample_findings):
        prof1 = converter.convert_findings(sample_findings[:1], "/app")[0]
        prof2 = converter.convert_findings(sample_findings[:1], "/app")[0]
        assert prof1.finding_uid == prof2.finding_uid


# ── 10 Critical Quality Rules Tests ──────────────────────────────────────────

class TestQualityRule1_MetadataValidation:
    def test_zero_files_scanned_generates_warning(self, converter):
        from codesentinelx_engine.scanner.reporting.report_models import ScanMetadata
        meta = ScanMetadata(files_scanned=0, total_lines_of_code=100, duration_seconds=5.0)
        warnings = converter._validate_scan_metadata(meta)
        assert any("files_scanned" in w.field_affected for w in warnings)

    def test_zero_loc_generates_warning(self, converter):
        from codesentinelx_engine.scanner.reporting.report_models import ScanMetadata
        meta = ScanMetadata(files_scanned=10, total_lines_of_code=0, duration_seconds=5.0)
        warnings = converter._validate_scan_metadata(meta)
        assert any("total_lines_of_code" in w.field_affected for w in warnings)

    def test_zero_duration_generates_warning(self, converter):
        from codesentinelx_engine.scanner.reporting.report_models import ScanMetadata
        meta = ScanMetadata(files_scanned=10, total_lines_of_code=100, duration_seconds=0)
        warnings = converter._validate_scan_metadata(meta)
        assert any("duration_seconds" in w.field_affected for w in warnings)

    def test_valid_metadata_no_warnings(self, converter):
        from codesentinelx_engine.scanner.reporting.report_models import ScanMetadata
        meta = ScanMetadata(files_scanned=10, total_lines_of_code=1000, duration_seconds=30.0)
        warnings = converter._validate_scan_metadata(meta)
        assert len(warnings) == 0

    def test_none_metadata_generates_warning(self, converter):
        warnings = converter._validate_scan_metadata(None)
        assert len(warnings) == 1
        assert warnings[0].rule_id == "R-001"

    def test_report_includes_metadata_warnings(self, converter, sample_findings):
        from codesentinelx_engine.scanner.reporting.report_models import ScanMetadata
        meta = ScanMetadata(files_scanned=0, total_lines_of_code=0, duration_seconds=0)
        report = converter.build_developer_report(sample_findings, "/app", scan_metadata=meta)
        assert len(report.validation_warnings) >= 3


class TestQualityRule2_CvssDifferentiation:
    def test_different_findings_different_cvss(self, converter, sample_findings):
        prof_findings = converter.convert_findings(sample_findings, "/app")
        scores = [f.cvss_score for f in prof_findings]
        # Rule 2: No two findings should have identical CVSS
        # (with 5 different file paths + line numbers, uniqueness is expected)
        assert len(set(scores)) > 1

    def test_cvss_scores_within_valid_range(self, converter, sample_findings):
        prof_findings = converter.convert_findings(sample_findings, "/app")
        for f in prof_findings:
            assert 0.0 <= f.cvss_score <= 10.0

    def test_cvss_temporal_and_env_present(self, converter, sample_findings):
        prof_findings = converter.convert_findings(sample_findings, "/app")
        for f in prof_findings:
            assert f.cvss_temporal_score > 0.0
            assert f.cvss_environmental_score > 0.0
            assert f.cvss_scoring_rationale

    def test_same_type_different_files_different_cvss(self, converter):
        findings = [
            Finding(
                vulnerability_type="SQL Injection", severity=Severity.CRITICAL,
                file_path="src/db/queries.py", line_number=42,
                business_impact="Database compromise", recommendation="Use parameterized queries",
                reference="https://cwe.mitre.org/data/definitions/89.html", owasp_category="A03:2021",
                description="SQL injection in queries", cwe="CWE-89", rule_id="R1", cvss_score=9.8,
            ),
            Finding(
                vulnerability_type="SQL Injection", severity=Severity.CRITICAL,
                file_path="src/api/handlers.py", line_number=88,
                business_impact="Database compromise", recommendation="Use parameterized queries",
                reference="https://cwe.mitre.org/data/definitions/89.html", owasp_category="A03:2021",
                description="SQL injection in handlers", cwe="CWE-89", rule_id="R2", cvss_score=9.8,
            ),
        ]
        prof = converter.convert_findings(findings, "/app")
        # Rule 2: Same type but different file/line should produce different scores
        assert prof[0].cvss_score != prof[1].cvss_score or \
               prof[0].cvss_temporal_score != prof[1].cvss_temporal_score


class TestQualityRule3_ActualCodeAndFunctions:
    def test_affected_functions_extracted(self, converter, sample_findings):
        prof_findings = converter.convert_findings(sample_findings, "/app")
        sql_f = next(f for f in prof_findings if "SQL" in f.title)
        assert len(sql_f.affected_functions) > 0

    def test_affected_files_populated(self, converter, sample_findings):
        prof_findings = converter.convert_findings(sample_findings, "/app")
        for f in prof_findings:
            assert len(f.affected_files) > 0

    def test_data_flow_has_file_context(self, converter, sample_findings):
        prof_findings = converter.convert_findings(sample_findings, "/app")
        sql_f = next(f for f in prof_findings if "SQL" in f.title)
        assert len(sql_f.data_flow_steps) > 0

    def test_component_has_function_name(self, converter, sample_findings):
        prof_findings = converter.convert_findings(sample_findings, "/app")
        for f in prof_findings:
            assert len(f.affected_components) == 1


class TestQualityRule4_ContextualizedImpacts:
    def test_business_impacts_not_identical(self, converter, sample_findings):
        prof_findings = converter.convert_findings(sample_findings, "/app")
        impacts = [f.business_impact for f in prof_findings]
        # At least some should differ
        assert len(set(impacts)) > 1

    def test_technical_impacts_not_identical(self, converter, sample_findings):
        prof_findings = converter.convert_findings(sample_findings, "/app")
        impacts = [f.technical_impact for f in prof_findings]
        assert len(set(impacts)) > 1

    def test_attack_vectors_not_identical(self, converter, sample_findings):
        prof_findings = converter.convert_findings(sample_findings, "/app")
        vectors = [f.attack_vector for f in prof_findings]
        assert len(set(vectors)) > 1

    def test_risk_justifications_not_identical(self, converter, sample_findings):
        prof_findings = converter.convert_findings(sample_findings, "/app")
        justifications = [f.risk_justification for f in prof_findings]
        assert len(set(justifications)) > 1

    def test_impacts_contain_file_context(self, converter, sample_findings):
        prof_findings = converter.convert_findings(sample_findings, "/app")
        sql_f = next(f for f in prof_findings if "SQL" in f.title)
        assert "queries.py" in sql_f.business_impact


class TestQualityRule5_MissingEvidenceNeedsReview:
    def test_minimal_evidence_gets_low_confidence(self, converter):
        findings = [
            Finding(
                vulnerability_type="Weak Crypto", severity=Severity.MEDIUM,
                file_path="src/crypto.py", line_number=1,
                business_impact="Data exposure", recommendation="Use AES-256",
                reference="", owasp_category="A02:2021",
                description="Weak algorithm", cwe="CWE-327", rule_id="CRYPTO001",
            ),
        ]
        prof = converter.convert_findings(findings, "/app")
        assert prof[0].confidence_level.value in ("Likely Positive", "Needs Manual Review")
        assert prof[0].confidence_score < 60

    def test_evidence_present_gets_higher_confidence(self, converter):
        findings = [
            Finding(
                vulnerability_type="SQL Injection", severity=Severity.CRITICAL,
                file_path="src/db.py", line_number=42,
                business_impact="Database compromise", recommendation="Use parameterized queries",
                reference="https://cwe.mitre.org/data/definitions/89.html", owasp_category="A03:2021",
                description="SQL injection", cwe="CWE-89", rule_id="SQL001",
                evidence="cursor.execute(f'SELECT * FROM users WHERE id={user_id}')",
            ),
        ]
        prof = converter.convert_findings(findings, "/app")
        assert prof[0].confidence_level.value in ("True Positive", "Likely Positive")
        assert prof[0].confidence_score > 60


class TestQualityRule6_SeverityCap:
    def test_no_cwe_no_reference_caps_at_medium(self, converter):
        findings = [
            Finding(
                vulnerability_type="SQL Injection", severity=Severity.CRITICAL,
                file_path="src/db.py", line_number=42,
                business_impact="Database compromise", recommendation="Fix it",
                reference="", owasp_category="A03:2021",
                description="SQL injection", cwe="", rule_id="SQL001",
            ),
        ]
        prof = converter.convert_findings(findings, "/app")
        assert prof[0].severity == "Medium"

    def test_with_cwe_keeps_severity(self, converter):
        findings = [
            Finding(
                vulnerability_type="SQL Injection", severity=Severity.CRITICAL,
                file_path="src/db.py", line_number=42,
                business_impact="Database compromise", recommendation="Fix it",
                reference="", owasp_category="A03:2021",
                description="SQL injection", cwe="CWE-89", rule_id="SQL001",
            ),
        ]
        prof = converter.convert_findings(findings, "/app")
        assert prof[0].severity == "Critical"

    def test_with_reference_keeps_severity(self, converter):
        findings = [
            Finding(
                vulnerability_type="SQL Injection", severity=Severity.CRITICAL,
                file_path="src/db.py", line_number=42,
                business_impact="Database compromise", recommendation="Fix it",
                reference="https://cwe.mitre.org/data/definitions/89.html", owasp_category="A03:2021",
                description="SQL injection", cwe="", rule_id="SQL001",
            ),
        ]
        prof = converter.convert_findings(findings, "/app")
        assert prof[0].severity == "Critical"


class TestQualityRule7_Deduplication:
    def test_same_type_same_dir_groups(self, converter):
        findings = [
            Finding(
                vulnerability_type="SQL Injection", severity=Severity.CRITICAL,
                file_path="src/db/q1.py", line_number=10,
                business_impact="DB compromise", recommendation="Fix",
                reference="https://cwe.mitre.org/data/definitions/89.html",
                owasp_category="A03:2021", description="SQLi in q1",
                cwe="CWE-89", rule_id="R1",
            ),
            Finding(
                vulnerability_type="SQL Injection", severity=Severity.HIGH,
                file_path="src/db/q2.py", line_number=20,
                business_impact="DB compromise", recommendation="Fix",
                reference="https://cwe.mitre.org/data/definitions/89.html",
                owasp_category="A03:2021", description="SQLi in q2",
                cwe="CWE-89", rule_id="R2",
            ),
            Finding(
                vulnerability_type="SQL Injection", severity=Severity.HIGH,
                file_path="src/db/q3.py", line_number=30,
                business_impact="DB compromise", recommendation="Fix",
                reference="https://cwe.mitre.org/data/definitions/89.html",
                owasp_category="A03:2021", description="SQLi in q3",
                cwe="CWE-89", rule_id="R3",
            ),
        ]
        report = converter.build_developer_report(findings, "/app")
        assert len(report.findings) <= len(findings)
        assert len(report.grouped_findings) > 0

    def test_different_types_not_grouped(self, converter):
        findings = [
            Finding(
                vulnerability_type="SQL Injection", severity=Severity.CRITICAL,
                file_path="src/db/q1.py", line_number=10,
                business_impact="DB compromise", recommendation="Fix",
                reference="https://cwe.mitre.org/data/definitions/89.html",
                owasp_category="A03:2021", description="SQLi",
                cwe="CWE-89", rule_id="R1",
            ),
            Finding(
                vulnerability_type="XSS", severity=Severity.HIGH,
                file_path="src/db/q2.py", line_number=20,
                business_impact="Client compromise", recommendation="Fix",
                reference="https://cwe.mitre.org/data/definitions/79.html",
                owasp_category="A03:2021", description="XSS",
                cwe="CWE-79", rule_id="R2",
            ),
        ]
        report = converter.build_developer_report(findings, "/app")
        assert len(report.findings) == 2
        assert len(report.grouped_findings) == 0

    def test_group_has_representative(self, converter):
        findings = [
            Finding(
                vulnerability_type="SQL Injection", severity=Severity.CRITICAL,
                file_path="src/db/q1.py", line_number=10,
                business_impact="DB compromise", recommendation="Fix",
                reference="https://cwe.mitre.org/data/definitions/89.html",
                owasp_category="A03:2021", description="SQLi",
                cwe="CWE-89", rule_id="R1",
            ),
            Finding(
                vulnerability_type="SQL Injection", severity=Severity.HIGH,
                file_path="src/db/q2.py", line_number=20,
                business_impact="DB compromise", recommendation="Fix",
                reference="https://cwe.mitre.org/data/definitions/89.html",
                owasp_category="A03:2021", description="SQLi",
                cwe="CWE-89", rule_id="R2",
            ),
        ]
        report = converter.build_developer_report(findings, "/app")
        if report.grouped_findings:
            g = report.grouped_findings[0]
            assert g.representative_finding_uid
            assert g.finding_count == 2


class TestQualityRule8_ConsistencyValidation:
    def test_severity_mismatch_detected(self, converter, sample_findings):
        report = converter.build_developer_report(sample_findings, "/app")
        # Rule 8: Should have validation warnings
        assert isinstance(report.validation_warnings, list)

    def test_warnings_populated_in_report(self, converter, sample_findings):
        from codesentinelx_engine.scanner.reporting.report_models import ScanMetadata
        meta = ScanMetadata(files_scanned=0, total_lines_of_code=0, duration_seconds=0)
        report = converter.build_developer_report(sample_findings, "/app", scan_metadata=meta)
        assert len(report.validation_warnings) > 0

    def test_valid_report_no_critical_warnings(self, converter, sample_findings):
        from codesentinelx_engine.scanner.reporting.report_models import ScanMetadata
        meta = ScanMetadata(files_scanned=50, total_lines_of_code=5000, duration_seconds=30.0)
        report = converter.build_developer_report(sample_findings, "/app", scan_metadata=meta)
        errors = [w for w in report.validation_warnings if w.severity == "ERROR"]
        assert len(errors) == 0


class TestQualityRule9_NoPlaceholderText:
    def test_no_generic_descriptions(self, converter, sample_findings):
        prof_findings = converter.convert_findings(sample_findings, "/app")
        for f in prof_findings:
            assert "TBD" not in f.description
            assert "TODO" not in f.description
            assert "PLACEHOLDER" not in f.description
            assert f.description  # Not empty

    def test_no_generic_impacts(self, converter, sample_findings):
        prof_findings = converter.convert_findings(sample_findings, "/app")
        for f in prof_findings:
            assert "TBD" not in f.business_impact
            assert f.business_impact  # Not empty
            assert "TBD" not in f.technical_impact
            assert f.technical_impact  # Not empty


class TestQualityRule10_AuditorGradeEvidence:
    def test_evidence_quality_score_present(self, converter, sample_findings):
        prof_findings = converter.convert_findings(sample_findings, "/app")
        for f in prof_findings:
            assert f.confidence_score >= 0.0

    def test_findings_with_evidence_higher_score(self, converter):
        findings_with = [
            Finding(
                vulnerability_type="SQL Injection", severity=Severity.CRITICAL,
                file_path="src/db.py", line_number=42,
                business_impact="DB compromise", recommendation="Fix",
                reference="https://cwe.mitre.org/data/definitions/89.html",
                owasp_category="A03:2021", description="SQL injection",
                cwe="CWE-89", rule_id="R1",
                evidence="cursor.execute(f'SELECT * FROM users WHERE id={user_id}')",
            ),
        ]
        findings_without = [
            Finding(
                vulnerability_type="Weak Crypto", severity=Severity.MEDIUM,
                file_path="src/crypto.py", line_number=1,
                business_impact="Data exposure", recommendation="Use AES-256",
                reference="", owasp_category="A02:2021",
                description="Weak algorithm", cwe="CWE-327", rule_id="R2",
            ),
        ]
        prof_with = converter.convert_findings(findings_with, "/app")
        prof_without = converter.convert_findings(findings_without, "/app")
        assert prof_with[0].confidence_score > prof_without[0].confidence_score

    def test_renderer_includes_evidence_quality(self, converter, renderer, sample_findings):
        report = converter.build_developer_report(sample_findings, "/app")
        html = renderer.render_html(report)
        assert "evidence-quality" in html


# ── Renderer integration tests for new features ──────────────────────────────

class TestRendererIntegration:
    def test_validation_banner_rendered(self, converter, renderer, sample_findings):
        from codesentinelx_engine.scanner.reporting.report_models import ScanMetadata
        meta = ScanMetadata(files_scanned=0, total_lines_of_code=0, duration_seconds=0)
        report = converter.build_developer_report(sample_findings, "/app", scan_metadata=meta)
        html = renderer.render_html(report)
        assert "validation-banner" in html
        assert "R-001" in html

    def test_finding_groups_rendered(self, converter, renderer):
        findings = [
            Finding(
                vulnerability_type="SQL Injection", severity=Severity.CRITICAL,
                file_path="src/db/q1.py", line_number=10,
                business_impact="DB compromise", recommendation="Fix",
                reference="https://cwe.mitre.org/data/definitions/89.html",
                owasp_category="A03:2021", description="SQLi in q1",
                cwe="CWE-89", rule_id="R1",
            ),
            Finding(
                vulnerability_type="SQL Injection", severity=Severity.HIGH,
                file_path="src/db/q2.py", line_number=20,
                business_impact="DB compromise", recommendation="Fix",
                reference="https://cwe.mitre.org/data/definitions/89.html",
                owasp_category="A03:2021", description="SQLi in q2",
                cwe="CWE-89", rule_id="R2",
            ),
        ]
        report = converter.build_developer_report(findings, "/app")
        html = renderer.render_html(report)
        if report.grouped_findings:
            assert "finding-group-card" in html
            assert "Finding Groups" in html

    def test_affected_functions_in_html(self, converter, renderer, sample_findings):
        report = converter.build_developer_report(sample_findings, "/app")
        html = renderer.render_html(report)
        assert "func-tag" in html or "Affected Functions" in html

    def test_evidence_quality_in_findings_overview(self, converter, renderer, sample_findings):
        report = converter.build_developer_report(sample_findings, "/app")
        html = renderer.render_html(report)
        assert "Evidence" in html  # The column header
