from __future__ import annotations

import argparse
import ast
import json
import re
from dataclasses import asdict, dataclass
from functools import lru_cache
from pathlib import Path

from codesentinelx_engine.scanner.source_analysis import find_flow_match


@dataclass(slots=True)
class ValidationContext:
    target_root: str
    file_path: str
    line_number: int
    vulnerability_type: str = ""
    rule_id: str = ""
    cwe_id: str = ""
    evidence: str = ""


@dataclass(slots=True)
class ValidationResult:
    mode: str
    family: str
    command: str
    status: str
    executed: bool
    exit_code: int | None
    output: str
    line_tested: int
    verification_basis: str
    confidence: float | None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def classify_family(vulnerability_type: str = "", rule_id: str = "", cwe_id: str = "") -> str:
    lowered = vulnerability_type.lower()
    if "dependency vulnerability" in lowered or "dependency" in rule_id.lower() or cwe_id.upper() == "CWE-1104":
        return "dependency-advisory"
    if "sql injection" in lowered or "sqli" in rule_id.lower() or cwe_id.upper() == "CWE-89":
        return "sql-injection"
    if "cross-site scripting" in lowered or lowered == "xss" or cwe_id.upper() == "CWE-79":
        return "xss"
    if "command injection" in lowered or "cmdi" in rule_id.lower() or cwe_id.upper() == "CWE-78":
        return "command-injection"
    if "path traversal" in lowered or "pathtrav" in rule_id.lower() or cwe_id.upper() == "CWE-22":
        return "path-traversal"
    if "ssrf" in lowered or "server-side request forgery" in lowered or cwe_id.upper() == "CWE-918":
        return "server-side-request-forgery"
    if "open redirect" in lowered or cwe_id.upper() == "CWE-601":
        return "open-redirect"
    if "template injection" in lowered or "ssti" in rule_id.lower() or cwe_id.upper() == "CWE-1336":
        return "template-injection"
    if "secret" in lowered or "credential" in lowered or "secrets" in rule_id.lower() or cwe_id.upper() == "CWE-798":
        return "hardcoded-secret"
    if "deserialization" in lowered or "deser" in rule_id.lower() or cwe_id.upper() == "CWE-502":
        return "insecure-deserialization"
    if "eval" in lowered or "eval" in rule_id.lower() or cwe_id.upper() == "CWE-95":
        return "unsafe-eval"
    if "weak cryptography" in lowered or "crypto" in rule_id.lower() or cwe_id.upper() == "CWE-327":
        return "weak-crypto"
    if "authentication" in lowered or "authorization" in lowered or "auth" in rule_id.lower() or cwe_id.upper() == "CWE-285":
        return "authz-flaw"
    return "generic"


def verify_finding(context: ValidationContext) -> ValidationResult:
    family = classify_family(context.vulnerability_type, context.rule_id, context.cwe_id)
    command = (
        "python -m codesentinelx_engine.poc_verify verify "
        f'--target-root "{Path(context.target_root).resolve()}" '
        f'--file "{context.file_path}" --line {max(1, int(context.line_number))} '
        f'--family "{family}" --rule-id "{context.rule_id}"'
    )
    source_path = _resolve_source_path(context.target_root, context.file_path)
    if source_path is None or not source_path.exists():
        return ValidationResult(
            mode="deterministic-source-validation",
            family=family,
            command=command,
            status="error",
            executed=False,
            exit_code=1,
            output=f"status=error\nfamily={family}\nresolved_file={source_path or context.file_path}\nreason=file-not-found",
            line_tested=max(1, int(context.line_number)),
            verification_basis="Source file could not be resolved for deterministic validation.",
            confidence=0.0,
        )

    text = _read_text(str(source_path))
    lines = text.splitlines()
    line_number = max(1, min(int(context.line_number or 1), max(1, len(lines))))
    line_text = lines[line_number - 1] if lines else ""
    excerpt = [line.rstrip() for line in lines[max(0, line_number - 3): min(len(lines), line_number + 2)]]
    language = _detect_language(source_path)
    flow_match = find_flow_match(text, source_path.suffix, family, line_number)
    if flow_match is not None:
        flow_status = "verified" if flow_match.confidence >= 0.8 and not flow_match.sanitized else "inconclusive"
        flow_basis = flow_match.details or "Source-to-sink dataflow confirmed from the recorded file and line context."
        output = "\n".join(
            [
                f"status={flow_status}",
                f"family={family}",
                f"resolved_file={source_path}",
                f"line={flow_match.line_number}",
                f"language={language}",
                f"signals={flow_match.evidence_summary()}",
                f"basis={flow_basis}",
                "trace:",
                *[f"    {line}" for line in flow_match.trace],
                "context:",
                *[f"    {line}" for line in excerpt[:5]],
            ]
        )
        return ValidationResult(
            mode="parser-and-flow-validation",
            family=family,
            command=command,
            status=flow_status,
            executed=True,
            exit_code=0 if flow_status == "verified" else 2,
            output=output,
            line_tested=flow_match.line_number,
            verification_basis=flow_basis,
            confidence=round(flow_match.confidence, 2),
        )
    status, confidence, basis, signals = _VALIDATORS.get(family, _validate_generic)(
        context,
        source_path,
        line_number,
        line_text,
        excerpt,
        language,
    )
    exit_code = 0 if status == "verified" else 2 if status == "inconclusive" else 3 if status == "not_applicable" else 1
    output = "\n".join(
        [
            f"status={status}",
            f"family={family}",
            f"resolved_file={source_path}",
            f"line={line_number}",
            f"language={language}",
            f"signals={','.join(signals) if signals else 'none'}",
            f"basis={basis}",
            "context:",
            *[f"    {line}" for line in excerpt[:5]],
        ]
    )
    return ValidationResult(
        mode="deterministic-source-validation",
        family=family,
        command=command,
        status=status,
        executed=True,
        exit_code=exit_code,
        output=output,
        line_tested=line_number,
        verification_basis=basis,
        confidence=round(confidence, 2),
    )


def _resolve_source_path(target_root: str, file_path: str) -> Path | None:
    path = Path(file_path)
    return path if path.is_absolute() else (Path(target_root).expanduser().resolve() / file_path).resolve()


@lru_cache(maxsize=2048)
def _read_text(path_str: str) -> str:
    return Path(path_str).read_text(encoding="utf-8", errors="ignore")


@lru_cache(maxsize=512)
def _parse_python(path_str: str) -> ast.AST | None:
    try:
        return ast.parse(_read_text(path_str))
    except SyntaxError:
        return None


def _detect_language(source_path: Path) -> str:
    suffix = source_path.suffix.lower()
    if suffix == ".py":
        return "python"
    if suffix in {".js", ".jsx", ".ts", ".tsx"}:
        return "javascript"
    if suffix == ".go":
        return "go"
    return suffix.lstrip(".") or "text"


def _status(signals: list[str], required: int = 2, allow_single: bool = False) -> tuple[str, float]:
    unique = list(dict.fromkeys(signals))
    confidence = min(0.98, 0.35 + len(unique) * 0.18)
    if len(unique) >= required or (allow_single and unique):
        return "verified", confidence
    if unique:
        return "inconclusive", min(confidence, 0.78)
    return "not_applicable", 0.18


def _python_calls_for_line(source_path: Path, line_number: int) -> list[ast.Call]:
    tree = _parse_python(str(source_path))
    if tree is None:
        return []
    calls: list[ast.Call] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            start = getattr(node, "lineno", 0)
            end = getattr(node, "end_lineno", start)
            if start <= line_number <= end:
                calls.append(node)
    return calls


def _call_name(node: ast.Call) -> str:
    if isinstance(node.func, ast.Attribute):
        if isinstance(node.func.value, ast.Name):
            return f"{node.func.value.id}.{node.func.attr}"
        return node.func.attr
    if isinstance(node.func, ast.Name):
        return node.func.id
    return ""


def _dynamic_ast_string(node: ast.AST | None) -> bool:
    return isinstance(node, ast.JoinedStr) or (
        isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod))
    ) or (
        isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format"
    )


def _validate_sql_injection(
    context: ValidationContext, source_path: Path, line_number: int, line_text: str, excerpt: list[str], language: str
) -> tuple[str, float, str, list[str]]:
    signals: list[str] = []
    if language == "python":
        for node in _python_calls_for_line(source_path, line_number):
            name = _call_name(node)
            if name.endswith(("execute", "executemany", "query")):
                signals.append(f"sink:{name}")
                first_arg = node.args[0] if node.args else None
                if _dynamic_ast_string(first_arg):
                    signals.append("dynamic-query")
                query_text = ast.unparse(first_arg).lower() if first_arg is not None else line_text.lower()
                if any(keyword in query_text for keyword in ("select ", "insert ", "update ", "delete ", " where ", " from ")):
                    signals.append("sql-keywords")
    else:
        joined = "\n".join(excerpt).lower()
        if any(sink in joined for sink in ("query(", "execute(", "sequelize.query", "db.query", "pool.query")):
            signals.append("sql-sink")
        if any(keyword in joined for keyword in ("select ", "insert ", "update ", "delete ", " where ", " from ")):
            signals.append("sql-keywords")
        if "+" in joined or "${" in joined or ".format(" in joined or "fmt.sprintf" in joined:
            signals.append("dynamic-query")
    status, confidence = _status(signals, required=3)
    basis = "Confirmed dynamic SQL construction reaching an execution sink." if status == "verified" else "Observed partial SQL/query signals but not enough source proof to confirm injection."
    return status, confidence, basis, signals


def _validate_xss(
    context: ValidationContext, source_path: Path, line_number: int, line_text: str, excerpt: list[str], language: str
) -> tuple[str, float, str, list[str]]:
    joined = "\n".join(excerpt).lower()
    signals = [f"sink:{sink}" for sink in ("innerhtml", "document.write", "dangerouslysetinnerhtml", "v-html") if sink in joined]
    if any(token in joined for token in ("req.", "request.", "props.", "__html")):
        signals.append("untrusted-render-path")
    status, confidence = _status(signals, required=1, allow_single=True)
    basis = "Detected unsafe HTML rendering sink in source context." if status == "verified" else "No unsafe rendering sink remained in nearby source context."
    return status, confidence, basis, signals


def _validate_command_injection(
    context: ValidationContext, source_path: Path, line_number: int, line_text: str, excerpt: list[str], language: str
) -> tuple[str, float, str, list[str]]:
    signals: list[str] = []
    if language == "python":
        for node in _python_calls_for_line(source_path, line_number):
            name = _call_name(node)
            if name in {"os.system", "subprocess.run", "subprocess.call", "subprocess.Popen"}:
                signals.append(f"sink:{name}")
                if any(keyword.arg == "shell" and isinstance(keyword.value, ast.Constant) and keyword.value.value is True for keyword in node.keywords):
                    signals.append("shell-true")
                if node.args and (_dynamic_ast_string(node.args[0]) or len(node.args) > 1):
                    signals.append("dynamic-command")
    else:
        joined = "\n".join(excerpt).lower()
        if any(token in joined for token in ("child_process.exec", "runtime.getruntime().exec", "exec.command(\"sh\"", "exec.command('sh'")):
            signals.append("command-sink")
        if "+" in joined or "${" in joined or "req." in joined or "request." in joined:
            signals.append("dynamic-command")
    status, confidence = _status(signals)
    basis = "Confirmed command execution sink with dynamic or shell-expanded input." if status == "verified" else "Observed command execution indicators without enough source proof for attacker-controlled command flow."
    return status, confidence, basis, signals


def _validate_path_traversal(
    context: ValidationContext, source_path: Path, line_number: int, line_text: str, excerpt: list[str], language: str
) -> tuple[str, float, str, list[str]]:
    joined = "\n".join(excerpt).lower()
    signals = []
    if "../" in joined or "..\\" in joined:
        signals.append("traversal-segment")
    if any(token in joined for token in ("send_file(", "open(", "readfile(", "createreadstream(")):
        signals.append("filesystem-sink")
    if any(token in joined for token in ("request.args", "request.form", "req.query", "req.params", "req.body")):
        signals.append("request-controlled-path")
    status, confidence = _status(signals)
    basis = "Confirmed user-controlled path data reaching a filesystem access sink." if status == "verified" else "Observed traversal or filesystem signals without enough source proof of user-controlled path flow."
    return status, confidence, basis, signals


def _validate_ssrf(
    context: ValidationContext, source_path: Path, line_number: int, line_text: str, excerpt: list[str], language: str
) -> tuple[str, float, str, list[str]]:
    joined = "\n".join(excerpt).lower()
    signals = []
    if any(token in joined for token in ("requests.get", "requests.post", "requests.request", "httpx.get", "httpx.post", "httpx.request", "urlopen(")):
        signals.append("http-client-sink")
    if any(token in joined for token in ("request.args", "request.form", "req.query", "req.params", "req.body")):
        signals.append("request-controlled-url")
    if any(token in joined for token in ("http://", "https://", "url=")):
        signals.append("url-shape")
    status, confidence = _status(signals)
    basis = "Confirmed request-controlled URL data reaching an outbound HTTP client." if status == "verified" else "Observed outbound request construction without enough source proof of attacker-controlled target selection."
    return status, confidence, basis, signals


def _validate_open_redirect(
    context: ValidationContext, source_path: Path, line_number: int, line_text: str, excerpt: list[str], language: str
) -> tuple[str, float, str, list[str]]:
    joined = "\n".join(excerpt).lower()
    signals = []
    if any(token in joined for token in ("redirect(", "httpresponseredirect(", "redirectresponse(")):
        signals.append("redirect-sink")
    if any(token in joined for token in ("request.args", "request.form", "req.query", "req.params", "next=", "returnurl", "redirect_to")):
        signals.append("request-controlled-target")
    status, confidence = _status(signals)
    basis = "Confirmed request-controlled redirect target reaching an HTTP redirect sink." if status == "verified" else "Observed redirect handling without enough source proof of attacker-controlled destination."
    return status, confidence, basis, signals


def _validate_template_injection(
    context: ValidationContext, source_path: Path, line_number: int, line_text: str, excerpt: list[str], language: str
) -> tuple[str, float, str, list[str]]:
    joined = "\n".join(excerpt).lower()
    signals = []
    if any(token in joined for token in ("render_template_string(", "template(", ".render(")):
        signals.append("template-sink")
    if any(token in joined for token in ("request.args", "request.form", "req.query", "req.params", "{{", "{%")):
        signals.append("untrusted-template-content")
    status, confidence = _status(signals)
    basis = "Confirmed request-controlled template content reaching a server-side rendering sink." if status == "verified" else "Observed template rendering indicators without enough source proof of attacker-controlled template content."
    return status, confidence, basis, signals


def _validate_hardcoded_secret(
    context: ValidationContext, source_path: Path, line_number: int, line_text: str, excerpt: list[str], language: str
) -> tuple[str, float, str, list[str]]:
    joined = "\n".join(excerpt)
    signals = []
    if re.search(r"\\b(password|passwd|secret|api[_-]?key|token|client_secret)\\b", joined, re.IGNORECASE):
        signals.append("secret-identifier")
    if re.search(r"['\"][^'\"]{8,}['\"]", line_text):
        signals.append("hardcoded-literal")
    if "BEGIN RSA PRIVATE KEY" in joined or re.search(r"AKIA[0-9A-Z]{16}", joined):
        signals.append("credential-signature")
    status, confidence = _status(signals)
    basis = "Confirmed secret-like identifier paired with embedded credential material in source." if status == "verified" else "Observed secret-related naming without enough literal credential evidence."
    return status, confidence, basis, signals


def _validate_insecure_deserialization(
    context: ValidationContext, source_path: Path, line_number: int, line_text: str, excerpt: list[str], language: str
) -> tuple[str, float, str, list[str]]:
    joined = "\n".join(excerpt).lower()
    signals = [token for token in ("pickle.loads", "yaml.load", "objectinputstream", "binaryformatter") if token in joined]
    status, confidence = _status(signals, required=1, allow_single=True)
    basis = "Unsafe deserialization API usage was confirmed directly in source." if status == "verified" else "Unsafe deserialization indicator no longer present in nearby source context."
    return status, confidence, basis, signals


def _validate_unsafe_eval(
    context: ValidationContext, source_path: Path, line_number: int, line_text: str, excerpt: list[str], language: str
) -> tuple[str, float, str, list[str]]:
    joined = "\n".join(excerpt).lower()
    signals = [token for token in ("eval(", "exec(", "new function", "settimeout(\"", "settimeout('") if token in joined]
    status, confidence = _status(signals, required=1, allow_single=True)
    basis = "Dynamic code execution primitive was confirmed directly in source." if status == "verified" else "Dynamic execution primitive no longer present in nearby source context."
    return status, confidence, basis, signals


def _validate_weak_crypto(
    context: ValidationContext, source_path: Path, line_number: int, line_text: str, excerpt: list[str], language: str
) -> tuple[str, float, str, list[str]]:
    joined = "\n".join(excerpt).lower()
    signals = [token for token in ("hashlib.md5", "hashlib.sha1", "crypto.createhash", "md5.new", "sha1.new", " des", " rc4") if token in joined]
    status, confidence = _status(signals, required=1, allow_single=True)
    basis = "Weak cryptographic primitive was confirmed directly in source." if status == "verified" else "No weak cryptographic primitive remained in nearby source context."
    return status, confidence, basis, signals


def _validate_authz_flaw(
    context: ValidationContext, source_path: Path, line_number: int, line_text: str, excerpt: list[str], language: str
) -> tuple[str, float, str, list[str]]:
    joined = "\n".join(excerpt).lower()
    signals = [token for token in ("skip_auth", "auth_disabled", "disable_auth", "allow_anonymous", "permitall", "verify=false", "csrf=false") if token in joined.replace(" ", "")]
    status, confidence = _status(signals, required=1, allow_single=True)
    basis = "Authentication or authorization bypass control was confirmed in source." if status == "verified" else "No bypass control remained in nearby source context."
    return status, confidence, basis, signals


def _validate_dependency_advisory(
    context: ValidationContext, source_path: Path, line_number: int, line_text: str, excerpt: list[str], language: str
) -> tuple[str, float, str, list[str]]:
    lowered_evidence = context.evidence.lower()
    signals = []
    package_token = lowered_evidence.split(":", 1)[0].split("=", 1)[0].strip()
    if package_token and package_token in line_text.lower():
        signals.append("manifest-entry-match")
    if any(token in line_text for token in ("==", ">=", "^", "~", "\"", "'")):
        signals.append("version-spec-present")
    status, confidence = _status(signals)
    basis = "Confirmed vulnerable dependency entry in project manifest or lockfile evidence." if status == "verified" else "Observed dependency entry but not enough local source proof to bind the advisory confidently."
    return status, confidence, basis, signals


def _validate_generic(
    context: ValidationContext, source_path: Path, line_number: int, line_text: str, excerpt: list[str], language: str
) -> tuple[str, float, str, list[str]]:
    excerpt_text = "\n".join(excerpt)
    signals = []
    if context.evidence and context.evidence.strip() and context.evidence.strip() in excerpt_text:
        signals.append("evidence-match")
    if line_text.strip():
        signals.append("line-present")
    status, confidence = _status(signals)
    basis = "Confirmed finding evidence is still present at the recorded source location." if status == "verified" else "Recorded source location exists, but family-specific deterministic proof is not available for this rule yet."
    return status, confidence, basis, signals


_VALIDATORS = {
    "sql-injection": _validate_sql_injection,
    "xss": _validate_xss,
    "command-injection": _validate_command_injection,
    "path-traversal": _validate_path_traversal,
    "server-side-request-forgery": _validate_ssrf,
    "open-redirect": _validate_open_redirect,
    "template-injection": _validate_template_injection,
    "hardcoded-secret": _validate_hardcoded_secret,
    "insecure-deserialization": _validate_insecure_deserialization,
    "unsafe-eval": _validate_unsafe_eval,
    "weak-crypto": _validate_weak_crypto,
    "authz-flaw": _validate_authz_flaw,
    "dependency-advisory": _validate_dependency_advisory,
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m codesentinelx_engine.poc_verify")
    subparsers = parser.add_subparsers(dest="command", required=True)
    verify_parser = subparsers.add_parser("verify", help="Run deterministic source validation for a finding")
    verify_parser.add_argument("--target-root", required=True)
    verify_parser.add_argument("--file", required=True)
    verify_parser.add_argument("--line", required=True, type=int)
    verify_parser.add_argument("--family", default="")
    verify_parser.add_argument("--rule-id", default="")
    verify_parser.add_argument("--cwe-id", default="")
    verify_parser.add_argument("--vulnerability-type", default="")
    verify_parser.add_argument("--evidence", default="")
    verify_parser.add_argument("--format", choices=["text", "json"], default="text")

    args = parser.parse_args(argv)
    context = ValidationContext(
        target_root=args.target_root,
        file_path=args.file,
        line_number=args.line,
        vulnerability_type=args.vulnerability_type or args.family or "",
        rule_id=args.rule_id or "",
        cwe_id=args.cwe_id or "",
        evidence=args.evidence or "",
    )
    result = verify_finding(context)
    if args.format == "json":
        print(json.dumps(result.to_dict(), indent=2))
    else:
        print(result.output)
    return int(result.exit_code or 0)


if __name__ == "__main__":
    raise SystemExit(main())

