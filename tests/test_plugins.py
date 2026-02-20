from pathlib import Path

from universal_security_scanner.models import Severity
from universal_security_scanner.plugins.loader import load_builtin_language_plugins


def _get_plugin(language: str):
    for plugin in load_builtin_language_plugins():
        if plugin.metadata.language == language:
            return plugin
    raise AssertionError(f"Missing plugin for {language}")


def test_python_plugin_detects_command_injection() -> None:
    plugin = _get_plugin("python")
    findings = plugin.scan_file(Path("service.py"), "import os\nos.system(user_input)")
    assert any(item.vulnerability_type == "Command Injection" for item in findings)


def test_javascript_plugin_detects_xss() -> None:
    plugin = _get_plugin("javascript")
    findings = plugin.scan_file(Path("index.js"), "el.innerHTML = userHtml")
    assert any(item.vulnerability_type == "Cross-Site Scripting (XSS)" for item in findings)


def test_go_plugin_detects_weak_crypto() -> None:
    plugin = _get_plugin("go")
    findings = plugin.scan_file(Path("main.go"), "_ = md5.New()")
    assert any(item.severity in {Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL} for item in findings)
