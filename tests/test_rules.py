from pathlib import Path

from codesentinelx_engine.models import Severity
from codesentinelx_engine.scanner.rules.builtin_rules import build_builtin_file_rules


def _scan_text(path: str, content: str):
    findings = []
    rules = build_builtin_file_rules()
    for rule in rules:
        findings.extend(rule.scan_file(Path(path), content))
    return findings


def test_detects_sql_injection_pattern() -> None:
    content = 'query = "SELECT * FROM users WHERE id = " + user_input\ncursor.execute(query)'
    findings = _scan_text("app.py", content)

    assert any(item.vulnerability_type == "SQL Injection" for item in findings)


def test_detects_hardcoded_secret() -> None:
    content = "API_KEY = 'my_super_secret_token_12345'"
    findings = _scan_text("settings.py", content)

    assert any(item.vulnerability_type == "Hardcoded Secrets / Credentials" for item in findings)


def test_detects_eval_usage() -> None:
    content = "result = eval(user_supplied_expression)"
    findings = _scan_text("calc.py", content)

    assert any(item.vulnerability_type == "Unsafe eval usage" for item in findings)


def test_detects_backend_ssrf_pattern() -> None:
    content = "response = requests.get(request.args['target_url'])"
    findings = _scan_text("api.py", content)

    assert any(item.vulnerability_type == "Server-Side Request Forgery (SSRF)" for item in findings)


def test_detects_weak_crypto_pattern() -> None:
    content = "digest = hashlib.md5(password.encode()).hexdigest()"
    findings = _scan_text("auth.py", content)

    assert any(item.vulnerability_type == "Weak Cryptography Usage" for item in findings)


def test_detects_sensitive_logging_pattern() -> None:
    content = 'logger.info("token=%s", auth_token)'
    findings = _scan_text("logging.py", content)

    assert any(item.vulnerability_type == "Sensitive Data Logged" for item in findings)

