from pathlib import Path

from codesentinelx_engine.models import Severity
from codesentinelx_engine.plugins.loader import load_builtin_language_plugins


def _get_plugin(language: str):
    for plugin in load_builtin_language_plugins():
        if plugin.metadata.language == language:
            return plugin
    raise AssertionError(f"Missing plugin for {language}")


def test_python_plugin_detects_command_injection() -> None:
    plugin = _get_plugin("python")
    findings = plugin.scan_file(Path("service.py"), "import os\nos.system(user_input)")
    assert any(item.vulnerability_type == "Command Injection" for item in findings)


def test_python_plugin_detects_sql_injection_dataflow() -> None:
    plugin = _get_plugin("python")
    findings = plugin.scan_file(
        Path("service.py"),
        "user_id = request.args.get('id')\nquery = f\"SELECT * FROM users WHERE id = {user_id}\"\ncursor.execute(query)\n",
    )
    assert any(item.rule_id == "PY-A03-SQLI-FLOW-001" for item in findings)


def test_javascript_plugin_detects_xss() -> None:
    plugin = _get_plugin("javascript")
    findings = plugin.scan_file(Path("index.js"), "el.innerHTML = userHtml")
    assert any(item.vulnerability_type == "Cross-Site Scripting (XSS)" for item in findings)


def test_javascript_plugin_detects_prototype_pollution_flow() -> None:
    plugin = _get_plugin("javascript")
    findings = plugin.scan_file(Path("index.js"), "const payload = req.body\nObject.assign({}, payload)\n")
    assert any(item.rule_id == "JS-A08-POLLUTION-FLOW-001" for item in findings)


def test_python_plugin_detects_ssrf_dataflow() -> None:
    plugin = _get_plugin("python")
    findings = plugin.scan_file(
        Path("service.py"),
        "target = request.args.get('url')\nrequests.get(target)\n",
    )
    assert any(item.rule_id == "PY-A10-SSRF-FLOW-001" for item in findings)


def test_javascript_plugin_detects_sql_injection_dataflow() -> None:
    plugin = _get_plugin("javascript")
    findings = plugin.scan_file(
        Path("index.js"),
        "const id = req.query.id;\ndb.query(`SELECT * FROM users WHERE id = ${id}`);\n",
    )
    assert any(item.rule_id == "JS-A03-SQLI-FLOW-001" for item in findings)


def test_javascript_plugin_detects_path_traversal_flow() -> None:
    plugin = _get_plugin("javascript")
    findings = plugin.scan_file(
        Path("index.js"),
        "const file = req.query.file;\nfs.readFile(file, () => {});\n",
    )
    assert any(item.rule_id == "JS-A01-PATHTRAV-FLOW-001" for item in findings)


def test_go_plugin_detects_weak_crypto() -> None:
    plugin = _get_plugin("go")
    findings = plugin.scan_file(Path("main.go"), "_ = md5.New()")
    assert any(item.severity in {Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL} for item in findings)

