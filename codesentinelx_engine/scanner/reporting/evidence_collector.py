from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .report_models import (
    EvidenceItem,
    HTTPRequestEvidence,
    HTTPResponseEvidence,
    ReproductionStep,
)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _hash_content(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


EVIDENCE_TYPE_CODE_SNIPPET = "code_snippet"
EVIDENCE_TYPE_HTTP_EXCHANGE = "http_exchange"
EVIDENCE_TYPE_POC_NARRATIVE = "poc_narrative"
EVIDENCE_TYPE_VALIDATION = "validation_result"
EVIDENCE_TYPE_REPRODUCTION = "reproduction_steps"


@dataclass(slots=True)
class EvidenceCollectorConfig:
    include_http_evidence: bool = True
    include_code_snippets: bool = True
    include_poc_narrative: bool = True
    max_snippet_lines: int = 20
    max_http_body_bytes: int = 4096
    capture_request_headers: bool = True
    capture_response_headers: bool = True


class EvidenceCollector:
    def __init__(self, config: EvidenceCollectorConfig | None = None) -> None:
        self._config = config or EvidenceCollectorConfig()

    def _detect_language(self, file_path: str) -> str:
        ext_map = {
            ".py": "python", ".js": "javascript", ".ts": "typescript",
            ".jsx": "javascript", ".tsx": "typescript", ".java": "java",
            ".go": "go", ".rb": "ruby", ".php": "php", ".cs": "csharp",
            ".cpp": "cpp", ".c": "c", ".rs": "rust",
        }
        for ext, lang in ext_map.items():
            if file_path.endswith(ext):
                return lang
        return ""

    def collect_from_finding(
        self,
        *,
        finding_uid: str,
        vulnerability_type: str,
        file_path: str,
        line_number: int,
        evidence_string: str = "",
        source_code: str = "",
        language: str = "",
        poc_narrative: str = "",
        http_request_data: dict[str, Any] | None = None,
        http_response_data: dict[str, Any] | None = None,
        reproduction_steps: list[dict[str, str]] | None = None,
        validation_result: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> list[EvidenceItem]:
        items: list[EvidenceItem] = []
        if not language:
            language = self._detect_language(file_path)
        if self._config.include_code_snippets and (source_code or evidence_string):
            items.append(
                self._build_code_evidence(
                    finding_uid=finding_uid,
                    file_path=file_path,
                    line_number=line_number,
                    source_code=source_code or evidence_string,
                    language=language,
                )
            )
        if self._config.include_http_evidence and http_request_data:
            items.append(
                self._build_http_evidence(
                    finding_uid=finding_uid,
                    request_data=http_request_data,
                    response_data=http_response_data,
                )
            )
        if self._config.include_poc_narrative and poc_narrative:
            items.append(
                self._build_poc_evidence(
                    finding_uid=finding_uid,
                    narrative=poc_narrative,
                    metadata=metadata or {},
                )
            )
        if validation_result:
            items.append(
                self._build_validation_evidence(
                    finding_uid=finding_uid,
                    validation=validation_result,
                )
            )
        if reproduction_steps:
            items.append(
                self._build_reproduction_evidence(
                    finding_uid=finding_uid,
                    steps=reproduction_steps,
                )
            )
        return items

    def _build_code_evidence(
        self,
        *,
        finding_uid: str,
        file_path: str,
        line_number: int,
        source_code: str,
        language: str,
    ) -> EvidenceItem:
        lines = source_code.splitlines()
        if len(lines) > self._config.max_snippet_lines:
            start = max(0, line_number - 3)
            lines = lines[start : start + self._config.max_snippet_lines]
        snippet = "\n".join(lines)
        return EvidenceItem(
            evidence_id="",
            evidence_type=EVIDENCE_TYPE_CODE_SNIPPET,
            title=f"Source code at {file_path}:{line_number}",
            description=f"Relevant source code excerpt ({language})",
            hash_sha256=_hash_content(snippet),
            data={
                "finding_uid": finding_uid,
                "content": snippet,
                "file_path": file_path,
                "line_start": max(1, line_number - 2),
                "line_end": line_number + len(lines),
                "language": language,
                "evidence_category": "source_code",
            },
        )

    def _build_http_evidence(
        self,
        *,
        finding_uid: str,
        request_data: dict[str, Any],
        response_data: dict[str, Any] | None,
    ) -> EvidenceItem:
        req = HTTPRequestEvidence(
            method=str(request_data.get("method", "GET")).upper(),
            url=str(request_data.get("url", "")),
            headers=dict(request_data.get("headers", {}))
            if self._config.capture_request_headers
            else {},
            body=str(request_data.get("body", ""))[: self._config.max_http_body_bytes],
            content_type=str(request_data.get("content_type", "")),
        )
        resp: HTTPResponseEvidence | None = None
        if response_data:
            resp = HTTPResponseEvidence(
                status_code=int(response_data.get("status_code", 0)),
                headers=dict(response_data.get("headers", {}))
                if self._config.capture_response_headers
                else {},
                body=str(response_data.get("body", ""))[: self._config.max_http_body_bytes],
                content_type=str(response_data.get("content_type", "")),
            )
        request_content = f"{req.method} {req.url}\n{req.body}"
        return EvidenceItem(
            evidence_id="",
            evidence_type=EVIDENCE_TYPE_HTTP_EXCHANGE,
            title=f"HTTP request to {req.url}",
            description="Captured HTTP request/response pair",
            hash_sha256=_hash_content(request_content),
            http_request=req,
            http_response=resp,
            data={
                "finding_uid": finding_uid,
                "evidence_category": "http_exchange",
            },
        )

    def _build_poc_evidence(
        self,
        *,
        finding_uid: str,
        narrative: str,
        metadata: dict[str, Any],
    ) -> EvidenceItem:
        return EvidenceItem(
            evidence_id="",
            evidence_type=EVIDENCE_TYPE_POC_NARRATIVE,
            title="Proof of Concept",
            description="Step-by-step reproduction narrative",
            hash_sha256=_hash_content(narrative),
            data={
                "finding_uid": finding_uid,
                "content": narrative,
                **metadata,
                "evidence_category": "poc",
            },
        )

    def _build_validation_evidence(
        self,
        *,
        finding_uid: str,
        validation: dict[str, Any],
    ) -> EvidenceItem:
        status = validation.get("status", "unknown")
        basis = validation.get("verification_basis", "")
        output = validation.get("output", "")
        return EvidenceItem(
            evidence_id="",
            evidence_type=EVIDENCE_TYPE_VALIDATION,
            title=f"Validation result: {status}",
            description=f"Automated verification: {basis}",
            hash_sha256=_hash_content(output),
            data={
                "finding_uid": finding_uid,
                "content": output,
                "validation_status": status,
                "confidence": validation.get("confidence"),
                "mode": validation.get("mode", ""),
                "family": validation.get("family", ""),
                "evidence_category": "validation",
            },
        )

    def _build_reproduction_evidence(
        self,
        *,
        finding_uid: str,
        steps: list[dict[str, str]],
    ) -> EvidenceItem:
        reproduction_steps = [
            ReproductionStep(
                step_number=i + 1,
                action=step.get("action", ""),
                expected_result=step.get("expected", ""),
                actual_result=step.get("actual", ""),
                notes=step.get("notes", ""),
            )
            for i, step in enumerate(steps)
        ]
        narrative_lines = []
        for rs in reproduction_steps:
            narrative_lines.append(f"Step {rs.step_number}: {rs.action}")
            if rs.expected_result:
                narrative_lines.append(f"  Expected: {rs.expected_result}")
            if rs.actual_result:
                narrative_lines.append(f"  Actual: {rs.actual_result}")
        narrative = "\n".join(narrative_lines)
        return EvidenceItem(
            evidence_id="",
            evidence_type=EVIDENCE_TYPE_REPRODUCTION,
            title="Reproduction Steps",
            description=f"{len(reproduction_steps)}-step reproduction guide",
            hash_sha256=_hash_content(narrative),
            data={
                "finding_uid": finding_uid,
                "content": narrative,
                "reproduction_steps": [rs.__dict__ for rs in reproduction_steps],
                "evidence_category": "reproduction",
            },
        )
