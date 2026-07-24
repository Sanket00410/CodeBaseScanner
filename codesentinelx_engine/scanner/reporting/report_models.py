from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from ...models import Severity


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _generate_id(prefix: str, value: str) -> str:
    return f"{prefix}-{hashlib.sha256(value.encode()).hexdigest()[:12]}"


class Confidence(str, Enum):
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


class ConfidenceLevel(str, Enum):
    TRUE_POSITIVE = "True Positive"
    LIKELY_POSITIVE = "Likely Positive"
    NEEDS_MANUAL_REVIEW = "Needs Manual Review"
    POTENTIAL_FALSE_POSITIVE = "Potential False Positive"


class RemediationComplexity(str, Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"


class ReportType(str, Enum):
    EXECUTIVE = "executive"
    DEVELOPER = "developer"
    COMPLIANCE = "compliance"
    TECHNICAL = "technical"
    RETEST = "retest"
    EVIDENCE_APPENDIX = "evidence_appendix"
    ATTACK_NARRATIVE = "attack_narrative"
    ASSET_INVENTORY = "asset_inventory"
    API_INVENTORY = "api_inventory"
    THREAT_MODEL = "threat_model"


class Exploitability(str, Enum):
    EXPLOITABLE = "Exploitable"
    POC_AVAILABLE = "POC Available"
    THEORETICAL = "Theoretical"
    NOT_EXPLOITABLE = "Not Exploitable"


class RemediationStatus(str, Enum):
    OPEN = "Open"
    IN_PROGRESS = "In Progress"
    REMEDIATED = "Remediated"
    ACCEPTED = "Accepted"
    FALSE_POSITIVE = "False Positive"


class HTTPMethod(str, Enum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"
    OPTIONS = "OPTIONS"
    HEAD = "HEAD"


class DataFlowStepType(str, Enum):
    SOURCE = "Source"
    VALIDATION = "Validation"
    PROCESSING = "Processing"
    TRANSFORMATION = "Transformation"
    SINK = "Sink"


@dataclass(slots=True)
class CVSSVector:
    attack_vector: str = "N/A"
    attack_complexity: str = "N/A"
    privileges_required: str = "N/A"
    user_interaction: str = "N/A"
    scope: str = "N/A"
    confidentiality: str = "N/A"
    integrity: str = "N/A"
    availability: str = "N/A"

    def to_vector_string(self) -> str:
        return (
            f"CVSS:3.1/AV:{self.attack_vector}/AC:{self.attack_complexity}"
            f"/PR:{self.privileges_required}/UI:{self.user_interaction}"
            f"/S:{self.scope}/C:{self.confidentiality}/I:{self.integrity}/A:{self.availability}"
        )

    @classmethod
    def from_vector_string(cls, vector: str) -> "CVSSVector":
        parts = {}
        for segment in vector.split("/"):
            if ":" in segment:
                key, _, value = segment.partition(":")
                parts[key.strip()] = value.strip()
        return cls(
            attack_vector=parts.get("AV", "N/A"),
            attack_complexity=parts.get("AC", "N/A"),
            privileges_required=parts.get("PR", "N/A"),
            user_interaction=parts.get("UI", "N/A"),
            scope=parts.get("S", "N/A"),
            confidentiality=parts.get("C", "N/A"),
            integrity=parts.get("I", "N/A"),
            availability=parts.get("A", "N/A"),
        )

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass(slots=True)
class TaxonomyMapping:
    framework: str = ""
    version: str = ""
    category_id: str = ""
    category_name: str = ""
    subcategory_id: str = ""
    subcategory_name: str = ""
    url: str = ""

    def to_dict(self) -> dict[str, str]:
        return {k: v for k, v in asdict(self).items() if v}


@dataclass(slots=True)
class HTTPRequestEvidence:
    method: str = "GET"
    url: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    cookies: dict[str, str] = field(default_factory=dict)
    content_type: str = ""
    user_agent: str = ""
    timestamp: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class HTTPResponseEvidence:
    status_code: int = 0
    status_text: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    content_type: str = ""
    response_time_ms: int = 0
    timestamp: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class EvidenceItem:
    evidence_id: str = ""
    evidence_type: str = ""
    title: str = ""
    description: str = ""
    timestamp: str = ""
    hash_sha256: str = ""
    data: dict[str, Any] = field(default_factory=dict)
    http_request: HTTPRequestEvidence | None = None
    http_response: HTTPResponseEvidence | None = None
    confidence: str = "Medium"
    source_tool: str = "CodeSentinelX"
    redacted: bool = False

    def __post_init__(self) -> None:
        if not self.evidence_id:
            raw = f"{self.evidence_type}:{self.title}:{self.timestamp}"
            self.evidence_id = f"EV-{hashlib.sha256(raw.encode()).hexdigest()[:12]}"
        if not self.timestamp:
            self.timestamp = _now_iso()

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        if self.http_request:
            result["http_request"] = self.http_request.to_dict()
        if self.http_response:
            result["http_response"] = self.http_response.to_dict()
        return result


@dataclass(slots=True)
class ReproductionStep:
    step_number: int = 1
    action: str = ""
    expected_result: str = ""
    actual_result: str = ""
    notes: str = ""

    def to_dict(self) -> dict[str, str | int]:
        return asdict(self)


@dataclass(slots=True)
class RemediationGuidance:
    title: str = ""
    description: str = ""
    complexity: str = "Medium"
    effort_hours: float = 0.0
    affected_component: str = ""
    remediation_type: str = ""
    code_example: str = ""
    fixed_code_example: str = ""
    configuration_change: str = ""
    infrastructure_change: str = ""
    references: list[str] = field(default_factory=list)
    regression_test_guidance: str = ""
    retest_checklist: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class StructuredBusinessImpact:
    financial_risk: str = ""
    financial_exposure_usd: float = 0.0
    regulatory_risk: str = ""
    regulatory_frameworks: list[str] = field(default_factory=list)
    operational_risk: str = ""
    reputational_risk: str = ""
    data_sensitivity: str = ""
    asset_criticality: str = ""


@dataclass(slots=True)
class AffectedComponent:
    component_type: str = ""
    component_name: str = ""
    file_path: str = ""
    line_range: str = ""
    function_name: str = ""
    class_name: str = ""
    module_name: str = ""
    version: str = ""
    language: str = ""
    framework: str = ""

    def to_dict(self) -> dict[str, str]:
        return {k: v for k, v in asdict(self).items() if v}


@dataclass(slots=True)
class DataFlowStep:
    step_type: str = "Processing"
    description: str = ""
    location: str = ""
    code_reference: str = ""

    def to_dict(self) -> dict[str, str]:
        return {k: v for k, v in asdict(self).items() if v}


@dataclass(slots=True)
class ProfessionalFinding:
    finding_uid: str = ""
    vulnerability_id: str = ""
    title: str = ""
    severity: Severity = Severity.INFO
    cvss_score: float = 0.0
    cvss_vector: CVSSVector = field(default_factory=CVSSVector)
    cvss_vector_string: str = ""
    cvss_temporal_score: float = 0.0
    cvss_environmental_score: float = 0.0
    cvss_scoring_rationale: str = ""
    confidence: Confidence = Confidence.MEDIUM
    confidence_level: ConfidenceLevel = ConfidenceLevel.NEEDS_MANUAL_REVIEW
    confidence_explanation: str = ""
    confidence_score: float = 0.0
    exploitability: Exploitability = Exploitability.THEORETICAL

    description: str = ""
    technical_explanation: str = ""
    business_impact: str = ""
    technical_impact: str = ""
    attack_vector: str = ""
    attack_preconditions: list[str] = field(default_factory=list)
    likelihood: str = ""
    risk_justification: str = ""
    structured_business_impact: StructuredBusinessImpact = field(default_factory=StructuredBusinessImpact)

    source_location: str = ""
    sink_location: str = ""
    data_flow_steps: list[DataFlowStep] = field(default_factory=list)

    affected_assets: list[str] = field(default_factory=list)
    affected_endpoints: list[str] = field(default_factory=list)
    affected_parameters: list[str] = field(default_factory=list)
    affected_http_methods: list[str] = field(default_factory=list)
    affected_headers: list[str] = field(default_factory=list)
    affected_components: list[AffectedComponent] = field(default_factory=list)
    affected_files: list[str] = field(default_factory=list)
    affected_functions: list[str] = field(default_factory=list)

    attack_path: dict[str, Any] = field(default_factory=dict)
    prerequisites: list[str] = field(default_factory=list)
    required_permissions: list[str] = field(default_factory=list)
    risk_explanation: str = ""

    proof_of_concept: dict[str, Any] = field(default_factory=dict)
    reproduction_steps: list[ReproductionStep] = field(default_factory=list)
    expected_result: str = ""
    actual_result: str = ""
    validation_notes: str = ""
    root_cause_category: str = ""

    root_cause_analysis: str = ""
    remediation: RemediationGuidance = field(default_factory=RemediationGuidance)
    references: list[TaxonomyMapping] = field(default_factory=list)
    owasp_api_top10: str = ""
    mitre_attack_technique: str = ""
    mitre_capec_id: str = ""
    nist_800_53: str = ""
    compliance_mapping: dict[str, str] = field(default_factory=dict)

    evidence: list[EvidenceItem] = field(default_factory=list)
    code_snippet_vulnerable: str = ""
    code_snippet_fixed: str = ""

    file_path: str = ""
    line_number: int = ""
    rule_id: str = ""
    cwe_id: str = ""
    cwe_name: str = ""
    capec_id: str = ""
    capec_name: str = ""
    owasp_category: str = ""
    owasp_version: str = "2021"
    mitre_attack_id: str = ""
    mitre_attack_name: str = ""
    wasc_id: str = ""
    wasc_name: str = ""
    asvs_requirement: str = ""
    pci_dss_requirement: str = ""
    cve_id: str = ""

    created_at: str = ""
    updated_at: str = ""
    status: RemediationStatus = RemediationStatus.OPEN
    remediation_status: RemediationStatus = RemediationStatus.OPEN
    remediation_complexity: RemediationComplexity = RemediationComplexity.MEDIUM
    remediation_priority: int = 0

    source_code_references: list[str] = field(default_factory=list)
    evidence_screenshots: list[str] = field(default_factory=list)
    evidence_logs: list[str] = field(default_factory=list)

    chain_id: str = ""
    chain_step: int = 0
    chain_total_steps: int = 0

    def __post_init__(self) -> None:
        if not self.created_at:
            self.created_at = _now_iso()
        if not self.updated_at:
            self.updated_at = _now_iso()
        if not self.vulnerability_id:
            raw = f"{self.file_path}:{self.line_number}:{self.title}"
            self.vulnerability_id = _generate_id("VULN", raw)
        if not self.finding_uid:
            self.finding_uid = self.vulnerability_id
        default_vector = CVSSVector()
        if self.cvss_vector_string:
            self.cvss_vector = CVSSVector.from_vector_string(self.cvss_vector_string)
        elif self.cvss_vector.to_vector_string() != default_vector.to_vector_string():
            self.cvss_vector_string = self.cvss_vector.to_vector_string()

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_uid": self.finding_uid,
            "vulnerability_id": self.vulnerability_id,
            "title": self.title,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector.to_dict(),
            "cvss_vector_string": self.cvss_vector_string or self.cvss_vector.to_vector_string(),
            "cvss_temporal_score": self.cvss_temporal_score,
            "cvss_environmental_score": self.cvss_environmental_score,
            "cvss_scoring_rationale": self.cvss_scoring_rationale,
            "confidence": self.confidence,
            "confidence_level": self.confidence_level,
            "confidence_explanation": self.confidence_explanation,
            "confidence_score": self.confidence_score,
            "exploitability": self.exploitability,
            "description": self.description,
            "technical_explanation": self.technical_explanation,
            "business_impact": self.business_impact,
            "technical_impact": self.technical_impact,
            "attack_vector": self.attack_vector,
            "attack_preconditions": self.attack_preconditions,
            "likelihood": self.likelihood,
            "risk_justification": self.risk_justification,
            "source_location": self.source_location,
            "sink_location": self.sink_location,
            "data_flow_steps": [s.to_dict() for s in self.data_flow_steps],
            "affected_assets": self.affected_assets,
            "affected_endpoints": self.affected_endpoints,
            "affected_parameters": self.affected_parameters,
            "affected_http_methods": self.affected_http_methods,
            "affected_headers": self.affected_headers,
            "affected_components": [c.to_dict() for c in self.affected_components],
            "affected_files": self.affected_files,
            "affected_functions": self.affected_functions,
            "attack_path": self.attack_path,
            "prerequisites": self.prerequisites,
            "required_permissions": self.required_permissions,
            "risk_explanation": self.risk_explanation,
            "proof_of_concept": self.proof_of_concept,
            "reproduction_steps": [s.to_dict() for s in self.reproduction_steps],
            "expected_result": self.expected_result,
            "actual_result": self.actual_result,
            "validation_notes": self.validation_notes,
            "root_cause_category": self.root_cause_category,
            "root_cause_analysis": self.root_cause_analysis,
            "remediation": self.remediation.to_dict(),
            "references": [r.to_dict() for r in self.references],
            "owasp_api_top10": self.owasp_api_top10,
            "mitre_attack_technique": self.mitre_attack_technique,
            "mitre_capec_id": self.mitre_capec_id,
            "nist_800_53": self.nist_800_53,
            "compliance_mapping": self.compliance_mapping,
            "evidence": [e.to_dict() for e in self.evidence],
            "code_snippet_vulnerable": self.code_snippet_vulnerable,
            "code_snippet_fixed": self.code_snippet_fixed,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "rule_id": self.rule_id,
            "cwe_id": self.cwe_id,
            "cwe_name": self.cwe_name,
            "capec_id": self.capec_id,
            "capec_name": self.capec_name,
            "owasp_category": self.owasp_category,
            "owasp_version": self.owasp_version,
            "mitre_attack_id": self.mitre_attack_id,
            "mitre_attack_name": self.mitre_attack_name,
            "wasc_id": self.wasc_id,
            "wasc_name": self.wasc_name,
            "asvs_requirement": self.asvs_requirement,
            "pci_dss_requirement": self.pci_dss_requirement,
            "cve_id": self.cve_id,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "status": self.status,
            "remediation_status": self.remediation_status,
            "remediation_complexity": self.remediation_complexity,
            "remediation_priority": self.remediation_priority,
            "source_code_references": self.source_code_references,
            "evidence_screenshots": self.evidence_screenshots,
            "evidence_logs": self.evidence_logs,
            "chain_id": self.chain_id,
            "chain_step": self.chain_step,
            "chain_total_steps": self.chain_total_steps,
        }


@dataclass(slots=True)
class AttackChainStep:
    step_number: int = 1
    finding_uid: str = ""
    title: str = ""
    severity: str = ""
    description: str = ""
    entry_point: str = ""
    technique: str = ""
    mitre_id: str = ""
    impact: str = ""
    next_step_uid: str = ""
    attack_phase: str = ""
    mitre_tactic: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class AttackChain:
    chain_id: str = ""
    title: str = ""
    description: str = ""
    severity: str = "Critical"
    steps: list[AttackChainStep] = field(default_factory=list)
    final_impact: str = ""
    mitigation_summary: str = ""
    created_at: str = ""
    mitre_attack_mapping: list[str] = field(default_factory=list)
    entry_point_summary: str = ""
    kill_chain_phases: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.created_at:
            self.created_at = _now_iso()

    def to_dict(self) -> dict[str, Any]:
        return {
            "chain_id": self.chain_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "steps": [s.to_dict() for s in self.steps],
            "final_impact": self.final_impact,
            "mitigation_summary": self.mitigation_summary,
            "created_at": self.created_at,
            "total_steps": len(self.steps),
            "mitre_attack_mapping": self.mitre_attack_mapping,
            "entry_point_summary": self.entry_point_summary,
            "kill_chain_phases": self.kill_chain_phases,
        }


@dataclass(slots=True)
class AssetInventory:
    asset_id: str = ""
    asset_type: str = ""
    name: str = ""
    hostname: str = ""
    ip_address: str = ""
    ports: list[int] = field(default_factory=list)
    operating_system: str = ""
    services: list[str] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)
    environment: str = ""
    criticality: str = "Medium"
    finding_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v or k in {"finding_count", "ports"}}


@dataclass(slots=True)
class EndpointInventory:
    endpoint_id: str = ""
    method: str = "GET"
    path: str = ""
    full_url: str = ""
    parameters: list[str] = field(default_factory=list)
    headers_required: list[str] = field(default_factory=list)
    authentication_required: bool = False
    authorization_level: str = ""
    content_type: str = ""
    finding_count: int = 0
    risk_level: str = "Low"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class APIInventory:
    api_id: str = ""
    title: str = ""
    base_url: str = ""
    version: str = ""
    protocol: str = "REST"
    authentication_type: str = ""
    documentation_url: str = ""
    endpoints: list[EndpointInventory] = field(default_factory=list)
    finding_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "api_id": self.api_id,
            "title": self.title,
            "base_url": self.base_url,
            "version": self.version,
            "protocol": self.protocol,
            "authentication_type": self.authentication_type,
            "documentation_url": self.documentation_url,
            "endpoints": [e.to_dict() for e in self.endpoints],
            "finding_count": self.finding_count,
            "total_endpoints": len(self.endpoints),
        }


@dataclass(slots=True)
class AuthenticationAnalysis:
    method_detected: str = "Unknown"
    session_management: str = "Unknown"
    token_type: str = ""
    password_policy: str = "Unknown"
    mfa_implemented: bool = False
    session_timeout: str = "Unknown"
    findings: list[str] = field(default_factory=list)
    weaknesses: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class AuthorizationAnalysis:
    model_detected: str = "Unknown"
    rbac_implemented: bool = False
    abac_implemented: bool = False
    object_level_authorization: str = "Unknown"
    function_level_authorization: str = "Unknown"
    findings: list[str] = field(default_factory=list)
    weaknesses: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ThreatModel:
    trust_boundaries: list[str] = field(default_factory=list)
    entry_points: list[str] = field(default_factory=list)
    assets: list[str] = field(default_factory=list)
    threat_actors: list[str] = field(default_factory=list)
    attack_vectors: list[str] = field(default_factory=list)
    mitigations: list[str] = field(default_factory=list)
    risk_level: str = "Medium"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ScanMetadata:
    scanner_name: str = "CodeSentinelX"
    scanner_version: str = "1.0.0"
    scan_id: str = ""
    target_path: str = ""
    target_type: str = "codebase"
    started_at: str = ""
    completed_at: str = ""
    duration_seconds: float = 0.0
    files_scanned: int = 0
    total_lines_of_code: int = 0
    scan_role: str = "Security Analyst"
    scan_preset: str = "standard"
    tools_used: list[str] = field(default_factory=list)
    tools_attempted: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    scan_environment: str = "local"
    assessor_name: str = "CodeSentinelX Automated Scanner"
    organization: str = ""
    language_breakdown: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        result = {k: v for k, v in asdict(self).items() if v or k in {"duration_seconds", "files_scanned"}}
        return result


@dataclass(slots=True)
class AssessmentScope:
    scope_description: str = ""
    in_scope: list[str] = field(default_factory=list)
    out_of_scope: list[str] = field(default_factory=list)
    testing_types: list[str] = field(default_factory=list)
    methodology: str = "OWASP Testing Guide v4.2"
    compliance_frameworks: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


_INDUSTRY_BENCHMARKS: dict[str, dict[str, float]] = {
    "Finance": {"overall_min": 75, "app_sec_min": 80, "supply_chain_min": 70, "secrets_min": 85},
    "Healthcare": {"overall_min": 70, "app_sec_min": 75, "supply_chain_min": 65, "secrets_min": 80},
    "Technology": {"overall_min": 65, "app_sec_min": 70, "supply_chain_min": 60, "secrets_min": 75},
    "E-commerce": {"overall_min": 70, "app_sec_min": 75, "supply_chain_min": 65, "secrets_min": 80},
    "Government": {"overall_min": 80, "app_sec_min": 85, "supply_chain_min": 75, "secrets_min": 90},
    "General": {"overall_min": 60, "app_sec_min": 65, "supply_chain_min": 55, "secrets_min": 70},
}

_RISK_APPETITE_LEVELS = {
    "conservative": {"critical_max": 0, "high_max": 3, "medium_max": 10},
    "moderate": {"critical_max": 2, "high_max": 8, "medium_max": 25},
    "aggressive": {"critical_max": 5, "high_max": 15, "medium_max": 50},
}


@dataclass(slots=True)
class IndustryBenchmarkComparison:
    industry: str = ""
    benchmark_score: float = 0.0
    actual_score: float = 0.0
    gap: float = 0.0
    status: str = ""
    recommendations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class RiskAppetiteAssessment:
    appetite_level: str = "moderate"
    thresholds: dict[str, int] = field(default_factory=dict)
    findings_within_appetite: bool = True
    exceeded_categories: list[str] = field(default_factory=list)
    severity_breaches: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class SecurityPostureScores:
    overall_score: float = 0.0
    application_security_score: float = 0.0
    supply_chain_score: float = 0.0
    secrets_management_score: float = 0.0
    dependency_hygiene_score: float = 0.0
    logging_maturity_score: float = 0.0
    current_state: str = ""
    target_state: str = ""
    gap_analysis: str = ""
    industry_benchmarks: list[IndustryBenchmarkComparison] = field(default_factory=list)
    risk_appetite: RiskAppetiteAssessment = field(default_factory=RiskAppetiteAssessment)
    compliance_honesty_score: float = 0.0
    benchmark_industry: str = "General"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class RootCauseGrouping:
    root_cause: str = ""
    affected_findings: list[str] = field(default_factory=list)
    affected_finding_count: int = 0
    affected_functions: list[str] = field(default_factory=list)
    causal_links: list[str] = field(default_factory=list)
    business_risk: str = ""
    recommended_master_fix: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class SBOMEntry:
    package_name: str = ""
    version: str = ""
    pinned: bool = False
    source: str = ""
    risk_level: str = "Low"
    ecosystem: str = ""
    license: str = ""
    vulnerability_count: int = 0
    latest_version: str = ""
    deprecated: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class SecurityMetricsDashboard:
    mean_time_to_remediate_hours: float = 0.0
    risk_score: float = 0.0
    high_risk_density: float = 0.0
    technical_debt_hours: float = 0.0
    security_debt_score: float = 0.0
    compliance_readiness: float = 0.0
    findings_per_1000_loc: float = 0.0
    remediation_completion_rate: float = 0.0
    scan_coverage_percent: float = 0.0
    owasp_coverage_matrix: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ComplianceFrameworkMapping:
    framework_name: str = ""
    framework_version: str = ""
    compliant_controls: int = 0
    total_controls: int = 0
    compliance_percentage: float = 0.0
    finding_ids: list[str] = field(default_factory=list)
    gaps: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class FindingGroup:
    group_id: str = ""
    group_type: str = ""
    finding_count: int = 0
    representative_finding_uid: str = ""
    finding_uids: list[str] = field(default_factory=list)
    affected_files: list[str] = field(default_factory=list)
    aggregated_severity: str = "Info"
    description: str = ""
    remediation_summary: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ReportValidationWarning:
    rule_id: str = ""
    severity: str = "WARNING"
    message: str = ""
    field_affected: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class AssessmentLimitation:
    category: str = ""
    description: str = ""
    impact: str = ""
    recommendation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ProfessionalReportMetadata:
    report_type: str = "developer"
    report_title: str = ""
    generated_at: str = ""
    version: str = "1.0"
    classification: str = "Confidential"
    distribution: str = ""
    scan_metadata: ScanMetadata = field(default_factory=ScanMetadata)
    assessment_scope: AssessmentScope = field(default_factory=AssessmentScope)
    executive_summary_text: str = ""
    security_posture_summary: str = ""
    total_findings: int = 0
    severity_distribution: dict[str, int] = field(default_factory=dict)
    risk_score: float = 0.0
    risk_rating: str = "Low"
    security_posture_scores: SecurityPostureScores = field(default_factory=SecurityPostureScores)
    scan_statistics: dict[str, Any] = field(default_factory=dict)
    critical_risk_drivers: list[str] = field(default_factory=list)
    top_5_security_risks: list[str] = field(default_factory=list)
    business_impact_assessment: str = ""
    remediation_timeline: str = ""
    root_cause_groupings: list[RootCauseGrouping] = field(default_factory=list)
    sbom_entries: list[SBOMEntry] = field(default_factory=list)
    security_metrics: SecurityMetricsDashboard = field(default_factory=SecurityMetricsDashboard)
    compliance_mappings: list[ComplianceFrameworkMapping] = field(default_factory=list)
    assessment_limitations: list[AssessmentLimitation] = field(default_factory=list)
    scanner_validation_notes: list[str] = field(default_factory=list)
    known_assumptions: list[str] = field(default_factory=list)
    validation_status: str = "Automated scan with manual review recommended"
    manual_review_recommendations: list[str] = field(default_factory=list)
    risk_trend_summary: str = ""
    remediation_phases: dict[str, list[dict[str, Any]]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.generated_at:
            self.generated_at = _now_iso()

    def to_dict(self) -> dict[str, Any]:
        return {
            "report_type": self.report_type,
            "report_title": self.report_title,
            "generated_at": self.generated_at,
            "version": self.version,
            "classification": self.classification,
            "distribution": self.distribution,
            "scan_metadata": self.scan_metadata.to_dict(),
            "assessment_scope": self.assessment_scope.to_dict(),
            "executive_summary_text": self.executive_summary_text,
            "security_posture_summary": self.security_posture_summary,
            "total_findings": self.total_findings,
            "severity_distribution": self.severity_distribution,
            "risk_score": self.risk_score,
            "risk_rating": self.risk_rating,
            "security_posture_scores": self.security_posture_scores.to_dict(),
            "scan_statistics": self.scan_statistics,
            "critical_risk_drivers": self.critical_risk_drivers,
            "top_5_security_risks": self.top_5_security_risks,
            "business_impact_assessment": self.business_impact_assessment,
            "remediation_timeline": self.remediation_timeline,
            "root_cause_groupings": [r.to_dict() for r in self.root_cause_groupings],
            "sbom_entries": [s.to_dict() for s in self.sbom_entries],
            "security_metrics": self.security_metrics.to_dict(),
            "compliance_mappings": [c.to_dict() for c in self.compliance_mappings],
            "assessment_limitations": [l.to_dict() for l in self.assessment_limitations],
            "scanner_validation_notes": self.scanner_validation_notes,
            "known_assumptions": self.known_assumptions,
            "validation_status": self.validation_status,
            "manual_review_recommendations": self.manual_review_recommendations,
            "risk_trend_summary": self.risk_trend_summary,
            "remediation_phases": self.remediation_phases,
        }


@dataclass(slots=True)
class DeveloperReport:
    metadata: ProfessionalReportMetadata = field(default_factory=ProfessionalReportMetadata)
    executive_summary: str = ""
    assessment_scope: AssessmentScope = field(default_factory=AssessmentScope)
    target_inventory: list[AssetInventory] = field(default_factory=list)
    api_inventory: list[APIInventory] = field(default_factory=list)
    endpoint_inventory: list[EndpointInventory] = field(default_factory=list)
    authentication_analysis: AuthenticationAnalysis = field(default_factory=AuthenticationAnalysis)
    authorization_analysis: AuthorizationAnalysis = field(default_factory=AuthorizationAnalysis)
    attack_surface_analysis: str = ""
    threat_model: ThreatModel = field(default_factory=ThreatModel)
    security_posture_summary: str = ""
    findings: list[ProfessionalFinding] = field(default_factory=list)
    attack_chains: list[AttackChain] = field(default_factory=list)
    grouped_findings: list[FindingGroup] = field(default_factory=list)
    validation_warnings: list[ReportValidationWarning] = field(default_factory=list)
    overall_risk_summary: str = ""
    remediation_roadmap: list[dict[str, Any]] = field(default_factory=list)
    root_cause_groupings: list[RootCauseGrouping] = field(default_factory=list)
    sbom_entries: list[SBOMEntry] = field(default_factory=list)
    security_metrics: SecurityMetricsDashboard = field(default_factory=SecurityMetricsDashboard)
    compliance_mappings: list[ComplianceFrameworkMapping] = field(default_factory=list)
    assessment_limitations: list[AssessmentLimitation] = field(default_factory=list)
    security_posture_scores: SecurityPostureScores = field(default_factory=SecurityPostureScores)
    remediation_phases: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    known_assumptions: list[str] = field(default_factory=list)
    manual_review_recommendations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "metadata": self.metadata.to_dict(),
            "executive_summary": self.executive_summary,
            "assessment_scope": self.assessment_scope.to_dict(),
            "target_inventory": [t.to_dict() for t in self.target_inventory],
            "api_inventory": [a.to_dict() for a in self.api_inventory],
            "endpoint_inventory": [e.to_dict() for e in self.endpoint_inventory],
            "authentication_analysis": self.authentication_analysis.to_dict(),
            "authorization_analysis": self.authorization_analysis.to_dict(),
            "attack_surface_analysis": self.attack_surface_analysis,
            "threat_model": self.threat_model.to_dict(),
            "security_posture_summary": self.security_posture_summary,
            "findings": [f.to_dict() for f in self.findings],
            "attack_chains": [c.to_dict() for c in self.attack_chains],
            "grouped_findings": [g.to_dict() for g in self.grouped_findings],
            "validation_warnings": [w.to_dict() for w in self.validation_warnings],
            "overall_risk_summary": self.overall_risk_summary,
            "remediation_roadmap": self.remediation_roadmap,
            "root_cause_groupings": [r.to_dict() for r in self.root_cause_groupings],
            "sbom_entries": [s.to_dict() for s in self.sbom_entries],
            "security_metrics": self.security_metrics.to_dict(),
            "compliance_mappings": [c.to_dict() for c in self.compliance_mappings],
            "assessment_limitations": [l.to_dict() for l in self.assessment_limitations],
            "security_posture_scores": self.security_posture_scores.to_dict(),
            "remediation_phases": self.remediation_phases,
            "known_assumptions": self.known_assumptions,
            "manual_review_recommendations": self.manual_review_recommendations,
        }


@dataclass(slots=True)
class RoleBasedView:
    role: str = ""
    summary: str = ""
    action_items: list[str] = field(default_factory=list)
    metrics: dict[str, Any] = field(default_factory=dict)
    recommendations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ExecutiveReport:
    metadata: ProfessionalReportMetadata = field(default_factory=ProfessionalReportMetadata)
    risk_summary: str = ""
    business_impact_summary: str = ""
    key_findings: list[str] = field(default_factory=list)
    remediation_priorities: list[str] = field(default_factory=list)
    compliance_status: dict[str, str] = field(default_factory=dict)
    metrics: dict[str, Any] = field(default_factory=dict)
    role_based_views: list[RoleBasedView] = field(default_factory=list)
    scan_trend_summary: str = ""
    previous_scan_summary: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "metadata": self.metadata.to_dict(),
            "risk_summary": self.risk_summary,
            "business_impact_summary": self.business_impact_summary,
            "key_findings": self.key_findings,
            "remediation_priorities": self.remediation_priorities,
            "compliance_status": self.compliance_status,
            "metrics": self.metrics,
            "role_based_views": [v.to_dict() for v in self.role_based_views],
            "scan_trend_summary": self.scan_trend_summary,
            "previous_scan_summary": self.previous_scan_summary,
        }


@dataclass(slots=True)
class ComplianceReport:
    metadata: ProfessionalReportMetadata = field(default_factory=ProfessionalReportMetadata)
    framework_name: str = ""
    framework_version: str = ""
    findings_by_framework: dict[str, list[str]] = field(default_factory=dict)
    compliance_gaps: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "metadata": self.metadata.to_dict(),
            "framework_name": self.framework_name,
            "framework_version": self.framework_version,
            "findings_by_framework": self.findings_by_framework,
            "compliance_gaps": self.compliance_gaps,
            "recommendations": self.recommendations,
        }


@dataclass(slots=True)
class RetestReport:
    metadata: ProfessionalReportMetadata = field(default_factory=ProfessionalReportMetadata)
    original_report_id: str = ""
    retest_date: str = ""
    retest_results: list[dict[str, Any]] = field(default_factory=list)
    summary: str = ""
    remediation_validation: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "metadata": self.metadata.to_dict(),
            "original_report_id": self.original_report_id,
            "retest_date": self.retest_date,
            "retest_results": self.retest_results,
            "summary": self.summary,
            "remediation_validation": self.remediation_validation,
        }
