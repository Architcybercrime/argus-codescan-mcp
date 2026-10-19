"""Secret values echoed by scanners must not reach serialized reports."""

import asyncio
import json
from pathlib import Path

from argus.formatters.sarif import aggregated_report_to_sarif
from argus.models import (
    AggregatedReport,
    Finding,
    ScanResult,
    ScanType,
    Severity,
    redact_secret_literals,
)
from argus.tools import secrets


def test_redacts_bandit_hardcoded_password_messages():
    assert (
        redact_secret_literals("Possible hardcoded password: 'SuperS3cret!'")
        == "Possible hardcoded password: '[REDACTED]'"
    )
    assert (
        redact_secret_literals('Possible hardcoded password: "it\'s-a-secret"')
        == 'Possible hardcoded password: "[REDACTED]"'
    )


def test_leaves_other_messages_unchanged():
    for text in (
        'Possible hardcoded password assigned to: "password"',
        "User input in SQL query",
        "",
    ):
        assert redact_secret_literals(text) == text


def test_secret_not_in_sarif_output():
    finding = Finding(
        title="hardcoded_password_string",
        severity=Severity.LOW,
        scan_type=ScanType.SAST,
        tool="bandit",
        file="app.py",
        line=1,
        description="Possible hardcoded password: 'SuperS3cret!'",
        rule_id="B105",
    )
    report = AggregatedReport(
        target="/app",
        results=[
            ScanResult(tool="bandit", scan_type=ScanType.SAST, target="/app", findings=[finding])
        ],
    )

    sarif = json.dumps(aggregated_report_to_sarif(report.to_dict()))

    assert "SuperS3cret!" not in sarif
    assert "[REDACTED]" in sarif


def test_gitleaks_description_never_uses_match(monkeypatch, tmp_path):
    leak = {
        "RuleID": "generic-api-key",
        "File": "app.py",
        "StartLine": 3,
        "Match": "key=sk_live_123",
    }

    async def fake_run_command(cmd, timeout):
        report_path = cmd[cmd.index("--report-path") + 1]
        Path(report_path).write_text(json.dumps([leak]), encoding="utf-8")
        return 0, "", ""

    monkeypatch.setattr(secrets, "is_tool_available", lambda name: True)
    monkeypatch.setattr(secrets, "run_command", fake_run_command)

    result = asyncio.run(secrets.run_gitleaks(str(tmp_path)))

    assert "sk_live_123" not in json.dumps(result.to_dict())
    assert result.findings[0].description == "Potential secret matched rule: generic-api-key"
