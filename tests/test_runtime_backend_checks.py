from codesentinelx_engine.scanner import remote_targets


def test_cookie_flag_findings_detects_missing_flags() -> None:
    findings = remote_targets._cookie_flag_findings(
        "https://example.com/login",
        {"set-cookie": "sessionid=abc123; Path=/"},
    )

    finding_names = {item.vulnerability_type for item in findings}
    assert "Session Cookie Missing Secure Flag" in finding_names
    assert "Session Cookie Missing HttpOnly Flag" in finding_names
    assert "Session Cookie Missing SameSite Attribute" in finding_names


def test_public_api_path_helper() -> None:
    assert remote_targets._is_public_api_path("/swagger/index.html")
    assert remote_targets._is_public_api_path("/health")
    assert not remote_targets._is_public_api_path("/api/v1/users")

