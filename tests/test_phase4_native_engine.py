from pathlib import Path

from codesentinelx_engine.config import ScannerConfig
from codesentinelx_engine.scanner.engine import ScanEngine
from codesentinelx_engine.scanner.source_analysis import analyze_family


def test_framework_aware_js_sanitizer_marks_xss_flow_as_sanitized() -> None:
    matches = analyze_family(
        "const payload = req.body.comment;\nel.innerHTML = DOMPurify.sanitize(payload);\n",
        ".js",
        "xss",
    )
    assert matches
    assert matches[0].sanitized is True
    assert matches[0].confidence < 0.9


def test_framework_aware_python_redirect_sanitizer_marks_flow_as_sanitized() -> None:
    matches = analyze_family(
        "target = request.args.get('next')\n"
        "if url_has_allowed_host_and_scheme(target, {'example.com'}):\n"
        "    return redirect(url_has_allowed_host_and_scheme(target, {'example.com'}))\n",
        ".py",
        "open-redirect",
    )
    assert matches
    assert matches[0].sanitized is True


def test_scan_engine_reuses_file_scan_cache_between_runs(tmp_path: Path, monkeypatch) -> None:
    cache_file = tmp_path / "exports" / ".integrity" / "scan_cache.json"
    (tmp_path / "service.py").write_text(
        "user_id = request.args.get('id')\n"
        "query = f\"SELECT * FROM users WHERE id = {user_id}\"\n"
        "cursor.execute(query)\n",
        encoding="utf-8",
    )
    config = ScannerConfig(
        use_external_tools=False,
        use_native_code_analysis=True,
        native_analysis_languages=["python"],
        native_analysis_families=["sql-injection"],
        file_scan_workers=1,
        scan_cache_enabled=True,
        scan_cache_file=cache_file,
    )

    engine = ScanEngine(config)
    calls = {"count": 0}
    original = engine.native_scanner.scan_file

    def wrapped_scan_file(file_path: Path, content: str):
        calls["count"] += 1
        return original(file_path, content)

    monkeypatch.setattr(engine.native_scanner, "scan_file", wrapped_scan_file)
    first = engine.scan(tmp_path)
    second = engine.scan(tmp_path)

    assert first.findings
    assert second.findings
    assert cache_file.exists()
    assert calls["count"] == 1

