# Plugin SDK Guide

## Base Contract
Implement `BaseLanguagePlugin` from `universal_security_scanner.plugins.sdk.interfaces`.

Required:
- `metadata`: plugin id, language, version
- `supported_extensions`: file extensions handled
- `scan_file(file_path, content)`: return list of `Finding`

## Helper APIs
- `build_finding(...)` to map plugin results to normalized scanner findings.
- `matched_line_numbers(content, patterns)` for regex line extraction.

## Built-in Plugins
- Python: command injection, insecure deserialization, weak crypto
- JavaScript: XSS, unsafe eval, CORS misconfiguration
- Go: SQLi, command injection, weak crypto

## Adding New Plugins
1. Create file under `universal_security_scanner/plugins/builtin` or custom package.
2. Implement plugin class using SDK interface.
3. Register plugin in `universal_security_scanner/plugins/loader.py`.
4. Add tests under `tests/`.
