"""Tests for the Argus pull-request comment built from SARIF output."""

from __future__ import annotations

import json
from pathlib import Path

from argus.cli import main
from argus.formatters.sarif import aggregated_report_to_sarif
from argus.models import AggregatedReport, Finding, ScanResult, ScanType, Severity
from argus.pr_comment import (
    COMMENT_MARKER,
    build_pr_comment,
    load_sarif_reports,
    report_from_sarif,
)


def _finding(
    title: str,
    severity: Severity,
    *,
    tool: str = "semgrep",
    scan_type: ScanType = ScanType.SAST,
    rule_id: str = "",
    file: str = "app.py",
    line: int = 1,
    fix: str = "",
) -> Finding:
    return Finding(
        title=title,
        severity=severity,
        scan_type=scan_type,
        tool=tool,
        file=file,
        line=line,
        description=f"{title} description",
        rule_id=rule_id or title.lower().replace(" ", "-"),
        fix_guidance=fix,
    )


def _sarif(*results: ScanResult) -> dict:
    return aggregated_report_to_sarif(AggregatedReport(target=".", results=list(results)).to_dict())


def _write(path: Path, sarif: dict) -> Path:
    path.write_text(json.dumps(sarif), encoding="utf-8")
    return path


def test_report_from_sarif_round_trips_fields() -> None:
    sarif = _sarif(
        ScanResult(
            tool="semgrep",
            scan_type=ScanType.SAST,
            target=".",
            findings=[
                _finding(
                    "SQL injection",
                    Severity.HIGH,
                    rule_id="python.sqli",
                    file="db.py",
                    line=12,
                    fix="Use parameterised queries.",
                ),
                _finding("Weak hash", Severity.LOW, rule_id="python.md5"),
            ],
        )
    )

    report = report_from_sarif(sarif)

    assert [r["tool"] for r in report["results"]] == ["semgrep"]
    sqli, weak = report["results"][0]["findings"]
    assert sqli["severity"] == "high"
    assert sqli["rule_id"] == "python.sqli"
    assert sqli["file"] == "db.py"
    assert sqli["line"] == 12
    assert sqli["fix_guidance"] == "Use parameterised queries."
    assert sqli["scan_type"] == "sast"
    # The formatter copies the description into help when there is no guidance.
    assert weak["fix_guidance"] == ""


def test_comment_has_summary_table_and_top_five_suggestions() -> None:
    findings = [
        _finding(f"Issue {i}", sev, rule_id=f"rule-{i}", line=i)
        for i, sev in enumerate(
            [
                Severity.LOW,
                Severity.CRITICAL,
                Severity.MEDIUM,
                Severity.HIGH,
                Severity.HIGH,
                Severity.INFO,
                Severity.MEDIUM,
            ]
        )
    ]
    secrets = [
        _finding(
            "AWS key",
            Severity.CRITICAL,
            tool="gitleaks",
            scan_type=ScanType.SECRETS,
            rule_id="aws-access-token",
            file="config.py",
        )
    ]
    report = report_from_sarif(
        _sarif(
            ScanResult(tool="semgrep", scan_type=ScanType.SAST, target=".", findings=findings),
            ScanResult(tool="gitleaks", scan_type=ScanType.SECRETS, target=".", findings=secrets),
        )
    )

    body = build_pr_comment(report, scope_mode="changed", changed_count=3)

    assert body.startswith(COMMENT_MARKER)
    assert "Scanned **3** changed file(s)" in body
    assert "**8 finding(s)**" in body
    assert "| semgrep | 1 | 2 | 2 | 1 | 1 | 7 |" in body
    assert "| gitleaks | 1 | 0 | 0 | 0 | 0 | 1 |" in body
    assert "| **Total** | 2 | 2 | 2 | 1 | 1 | 8 |" in body
    assert "### Top 5 fix suggestion(s)" in body
    suggestions = [line for line in body.splitlines() if line[:3] in {"1. ", "2. ", "5. "}]
    assert "CRITICAL" in suggestions[0]
    assert "6. " not in body.split("<details>")[0]
    # Secrets without guidance get the built-in rotation advice.
    assert "Rotate" in body or "rotate" in body
    assert "Prompt for an AI assistant" in body


def test_comment_reports_no_findings_and_links() -> None:
    body = build_pr_comment(
        {"target": ".", "results": []},
        scope_mode="full",
        changed_count=120,
        run_url="https://github.com/o/r/actions/runs/1",
        dashboard_url="https://dash.example/runs/42",
    )

    assert "✅ **No findings.**" in body
    assert "full repository was scanned" in body
    assert "120 files changed" in body
    assert "[Cloud dashboard run](https://dash.example/runs/42)" in body
    assert "[Workflow run and SARIF artifact](https://github.com/o/r/actions/runs/1)" in body
    assert "fix suggestion" not in body


def test_comment_escapes_untrusted_text() -> None:
    report = {
        "target": ".",
        "results": [
            {
                "tool": "semgrep",
                "scan_type": "sast",
                "findings": [
                    {
                        "title": "Bad <img src=x> @octocat | pipe",
                        "severity": "high",
                        "scan_type": "sast",
                        "tool": "semgrep",
                        "file": "a`b.py",
                        "line": 3,
                        "rule_id": "r1",
                        "fix_guidance": "",
                    }
                ],
            }
        ],
    }

    body = build_pr_comment(report)
    # The AI prompt sits in a code fence, which GitHub renders literally.
    rendered, prompt = body.split("````text")

    assert "<img" not in rendered
    assert "&lt;img src=x&gt;" in rendered
    assert "\\| pipe" in rendered
    assert "`a'b.py:3`" in rendered
    assert "@octocat" not in body
    assert prompt.count("````") == 1


def test_empty_scope_ignores_missing_sarif(tmp_path: Path) -> None:
    report, missing = load_sarif_reports([tmp_path / "sast.sarif"])

    body = build_pr_comment(report, scope_mode="empty", missing_reports=missing)

    assert missing == [str(tmp_path / "sast.sarif")]
    assert "only deletions" in body
    assert "No results from" not in body


def test_pr_comment_cli_writes_markdown(tmp_path: Path, monkeypatch) -> None:
    sast = _write(
        tmp_path / "sast.sarif",
        _sarif(
            ScanResult(
                tool="bandit",
                scan_type=ScanType.SAST,
                target=".",
                findings=[_finding("Use of exec", Severity.MEDIUM, tool="bandit")],
            )
        ),
    )
    out = tmp_path / "comment.md"
    monkeypatch.setenv("ARGUS_DASHBOARD_URL", "https://dash.example/runs/7")

    code = main(
        [
            "ci",
            "pr-comment",
            "--sarif",
            str(sast),
            str(tmp_path / "secrets.sarif"),
            "--scope-mode",
            "changed",
            "--changed-count",
            "",
            "--output",
            str(out),
        ]
    )

    assert code == 0
    body = out.read_text(encoding="utf-8")
    assert "| bandit | 0 | 0 | 1 | 0 | 0 | 1 |" in body
    assert "No results from `secrets.sarif`" in body
    assert "https://dash.example/runs/7" in body
