from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.error import URLError
from urllib.request import Request, urlopen


@dataclass(slots=True)
class AIProviderConfig:
    enabled: bool
    provider: str
    model: str
    url: str
    timeout_sec: int
    remediation_max_findings: int
    prioritization_max_findings: int


def load_ai_provider_config() -> AIProviderConfig:
    provider = os.getenv("USS_AI_REMEDIATION_PROVIDER", "").strip().lower()
    model = os.getenv("USS_AI_OLLAMA_MODEL", "").strip()
    if not provider and model:
        provider = "ollama"
    enabled = provider == "ollama" and bool(model)
    return AIProviderConfig(
        enabled=enabled,
        provider=provider or "local-evidence-driven",
        model=model or "parser-flow-validation-v2",
        url=os.getenv("USS_AI_OLLAMA_URL", "http://127.0.0.1:11434/api/generate").strip(),
        timeout_sec=max(5, int(os.getenv("USS_AI_OLLAMA_TIMEOUT_SEC", "45") or "45")),
        remediation_max_findings=max(1, int(os.getenv("USS_AI_REMEDIATION_MAX_FINDINGS", "8") or "8")),
        prioritization_max_findings=max(1, int(os.getenv("USS_AI_PRIORITIZATION_MAX_FINDINGS", "18") or "18")),
    )


def build_provider_status(config: AIProviderConfig, *, ready: bool = False, detail: str = "") -> dict[str, object]:
    if not config.enabled:
        return {
            "mode": "context-aware",
            "provider": "local-evidence-driven",
            "model": "parser-flow-validation-v2",
            "status": "ready",
            "grounded_generation": True,
            "prioritization_status": "ready",
            "detail": detail or "Local evidence-backed remediation is active. Provider-backed AI is disabled.",
        }
    return {
        "mode": "context-aware",
        "provider": config.provider,
        "model": config.model,
        "status": "ready" if ready else "degraded",
        "grounded_generation": True,
        "prioritization_status": "ready" if ready else "fallback",
        "detail": detail or ("Provider-backed grounded remediation is active." if ready else "Provider was configured but no grounded output was accepted."),
    }


def generate_grounded_remediation(finding: dict[str, Any], target_root: str, config: AIProviderConfig) -> dict[str, Any] | None:
    if not config.enabled:
        return None
    excerpt = _read_context_excerpt(target_root, str(finding.get("file_path") or ""), int(finding.get("line_number", 1) or 1))
    prompt = _build_remediation_prompt(finding, excerpt)
    raw = _ollama_generate(prompt, config)
    parsed = _parse_json_payload(raw)
    if not isinstance(parsed, dict):
        return None
    confidence = _normalize_confidence(parsed.get("fix_confidence_score"), finding)
    return {
        "remediation_summary": _normalize_text(parsed.get("remediation_summary"), limit=800),
        "suggested_fix": _normalize_text(parsed.get("suggested_fix"), limit=2000),
        "validation_steps": _normalize_validation_steps(parsed.get("validation_steps")),
        "fix_confidence_score": confidence,
        "fix_confidence_label": _confidence_label(confidence),
        "grounding_notes": _normalize_text(parsed.get("grounding_notes"), limit=600),
        "manual_review_required": bool(parsed.get("manual_review_required", False)),
    }


def generate_prioritization_plan(findings: list[dict[str, Any]], config: AIProviderConfig) -> dict[str, list[dict[str, Any]]] | None:
    if not config.enabled:
        return None
    shortlisted = sorted(
        (item for item in findings if bool(item.get("ai_fix_grounded"))),
        key=lambda item: -float(item.get("risk_priority_score", item.get("cvss_score", 0.0))),
    )[: config.prioritization_max_findings]
    if not shortlisted:
        return None
    prompt = _build_prioritization_prompt(shortlisted)
    raw = _ollama_generate(prompt, config)
    parsed = _parse_json_payload(raw)
    if not isinstance(parsed, dict):
        return None
    plan: dict[str, list[dict[str, Any]]] = {}
    for window in ("8_hours", "24_hours", "72_hours"):
        entries = parsed.get(window)
        if not isinstance(entries, list):
            continue
        rows: list[dict[str, Any]] = []
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            uid = str(entry.get("finding_uid") or "").strip()
            if not uid:
                continue
            rows.append(
                {
                    "finding_uid": uid,
                    "why_first": _normalize_text(entry.get("why_first"), limit=500),
                    "priority_score": float(entry.get("priority_score") or 0.0),
                    "fix_confidence_score": float(entry.get("fix_confidence_score") or 0.0),
                }
            )
        if rows:
            plan[window] = rows
    return plan or None


def _ollama_generate(prompt: str, config: AIProviderConfig) -> str:
    payload = json.dumps(
        {
            "model": config.model,
            "stream": False,
            "format": "json",
            "prompt": prompt,
        }
    ).encode("utf-8")
    request = Request(
        config.url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=config.timeout_sec) as response:
            body = response.read().decode("utf-8", errors="ignore")
    except URLError:
        return ""
    if not body:
        return ""
    with suppress_json_error():
        parsed = json.loads(body)
        if isinstance(parsed, dict):
            return str(parsed.get("response") or "")
    return body


def _build_remediation_prompt(finding: dict[str, Any], excerpt: str) -> str:
    return "\n".join(
        [
            "You are assisting a secure code analysis platform.",
            "Use only the supplied evidence. Do not invent vulnerabilities, exploits, or unsupported code changes.",
            "Return strict JSON with keys remediation_summary, suggested_fix, validation_steps, fix_confidence_score, grounding_notes, manual_review_required.",
            "",
            f"Title: {finding.get('vulnerability_title') or finding.get('vulnerability_type')}",
            f"Severity: {finding.get('severity')}",
            f"CWE: {finding.get('cwe_id')}",
            f"OWASP: {finding.get('owasp_mapping')}",
            f"Rule ID: {finding.get('rule_id')}",
            f"File: {finding.get('file_path')}:{finding.get('line_number')}",
            f"Recommendation: {finding.get('recommendation')}",
            f"Original snippet: {finding.get('original_code') or finding.get('vulnerable_code_snippet') or finding.get('evidence')}",
            f"Current candidate fix: {finding.get('fixed_code') or ''}",
            f"Validation status: {(finding.get('active_poc') or {}).get('status')}",
            f"Validation basis: {(finding.get('active_poc') or {}).get('verification_basis')}",
            f"Validation output: {(finding.get('active_poc') or {}).get('output')}",
            f"Dependency reachability: {finding.get('dependency_reachability')}",
            "Source context:",
            excerpt or "(unavailable)",
        ]
    )


def _build_prioritization_prompt(findings: list[dict[str, Any]]) -> str:
    rows = []
    for item in findings:
        rows.append(
            {
                "finding_uid": item.get("finding_uid"),
                "title": item.get("vulnerability_title") or item.get("vulnerability_type"),
                "severity": item.get("severity"),
                "file_path": item.get("file_path"),
                "line_number": item.get("line_number"),
                "priority_score": item.get("risk_priority_score"),
                "validation_status": (item.get("active_poc") or {}).get("status"),
                "validation_basis": (item.get("active_poc") or {}).get("verification_basis"),
                "fix_confidence_score": item.get("ai_fix_confidence_score"),
                "recommendation": item.get("recommendation"),
            }
        )
    return "\n".join(
        [
            "You are ranking already-detected security findings for remediation planning.",
            "Use only the supplied evidence. Do not create or remove findings.",
            "Return strict JSON with keys 8_hours, 24_hours, 72_hours. Each value must be a list of objects with finding_uid, why_first, priority_score, fix_confidence_score.",
            f"Findings: {json.dumps(rows, ensure_ascii=True)}",
        ]
    )


def _read_context_excerpt(target_root: str, file_path: str, line_number: int, radius: int = 3) -> str:
    source_path = Path(target_root).expanduser().resolve() / file_path
    if not source_path.exists():
        return ""
    try:
        lines = source_path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return ""
    if not lines:
        return ""
    start = max(0, line_number - radius - 1)
    end = min(len(lines), line_number + radius)
    return "\n".join(f"{index + 1}: {line}" for index, line in enumerate(lines[start:end], start=start))


def _parse_json_payload(raw: str) -> dict[str, Any] | list[Any] | None:
    text = (raw or "").strip()
    if not text:
        return None
    with suppress_json_error():
        return json.loads(text)
    match = re.search(r"(\{.*\}|\[.*\])", text, flags=re.DOTALL)
    if match:
        with suppress_json_error():
            return json.loads(match.group(1))
    return None


def _normalize_text(value: Any, *, limit: int) -> str:
    text = str(value or "").strip()
    return text[:limit].strip()


def _normalize_validation_steps(value: Any) -> str:
    if isinstance(value, list):
        lines = [str(item).strip() for item in value if str(item).strip()]
        return "\n".join(f"{index}. {line}" for index, line in enumerate(lines, start=1))
    return _normalize_text(value, limit=1200)


def _normalize_confidence(value: Any, finding: dict[str, Any]) -> float:
    try:
        numeric = float(value)
    except (TypeError, ValueError):
        numeric = float(finding.get("ai_fix_confidence_score") or 0.0)
    return max(0.0, min(1.0, numeric))


def _confidence_label(score: float) -> str:
    if score >= 0.82:
        return "High"
    if score >= 0.58:
        return "Medium"
    return "Low"


class suppress_json_error:
    def __enter__(self) -> suppress_json_error:
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        return exc_type is not None and issubclass(exc_type, (json.JSONDecodeError, TypeError, ValueError))
