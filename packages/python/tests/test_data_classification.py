"""Data classification on findings (#61)."""

from __future__ import annotations

import argparse
import json

import pytest

from argus.cli import _emit, _filter_classification, _parse_classifications
from argus.formatters.sarif import aggregated_report_to_sarif
from argus.models import Finding, ScanType, Severity
from argus.policy import PolicyConfig, Suppression, apply_policy
from argus.tools.code import run_native_languages
from argus.utils import refresh_report_summary


def _finding(rule_id: str, severity: str, classification: str = "unset") -> dict:
    return {
        "title": rule_id,
        "severity": severity,
        "scan_type": "sast",
        "tool": "argus-languages",
        "file": "app.py",
        "line": 1,
        "rule_id": rule_id,
        "data_classification": classification,
    }


def _report() -> dict:
    findings = [
        _finding("pii-email-in-logs", "medium", "pii"),
        _finding("hipaa-phi-in-logs", "high", "phi"),
        _finding("db-connection-string", "high", "confidential"),
        _finding("command-injection", "high"),
    ]
    return {
        "target": "/app",
        "summary": {"total_findings": len(findings), "extra": "kept"},
        "results": [{"tool": "argus-languages", "scan_type": "sast", "findings": findings}],
    }


def test_finding_defaults_to_unset():
    finding = Finding(title="t", severity=Severity.LOW, scan_type=ScanType.SAST, tool="x")
    assert finding.to_dict()["data_classification"] == "unset"


def test_built_in_rules_set_classification(tmp_path):
    (tmp_path / "app.py").write_text(
        "import logging\nlogger = logging.getLogger()\n"
        'logger.info(f"user {user.email}")\n'
        'logger.info("patient diagnosis %s", d)\n'
        'db = "postgres://u:p@h/db"\n'
    )
    import asyncio

    result = asyncio.run(run_native_languages(str(tmp_path)))
    by_rule = {f.rule_id: f.data_classification for f in result.findings}

    assert by_rule["pii-email-in-logs"] == "pii"
    assert by_rule["hipaa-phi-in-logs"] == "phi"
    assert by_rule["db-connection-string"] == "confidential"


def test_parse_classifications_normalises_and_rejects_unknown():
    assert _parse_classifications(" PHI, pii ,pii") == "phi,pii"
    with pytest.raises(argparse.ArgumentTypeError):
        _parse_classifications("pii,bogus")
    with pytest.raises(argparse.ArgumentTypeError):
        _parse_classifications(" , ")


def test_filter_classification_keeps_requested_tags_only():
    report = _report()

    filtered = _filter_classification(report, "pii,unset")

    rules = [f["rule_id"] for f in filtered["results"][0]["findings"]]
    assert rules == ["pii-email-in-logs", "command-injection"]
    assert len(report["results"][0]["findings"]) == 4  # input not mutated
    assert _filter_classification(report, None) is report


def test_refresh_report_summary_recounts_and_keeps_extra_keys():
    report = _filter_classification(_report(), "phi")

    refresh_report_summary(report)

    assert report["summary"]["total_findings"] == 1
    assert report["summary"]["by_severity"]["high"] == 1
    assert report["summary"]["by_tool"] == {"argus-languages": 1}
    assert report["summary"]["extra"] == "kept"
    assert report["results"][0]["summary"]["total"] == 1


def test_classification_filter_does_not_change_fail_on(tmp_path, capsys):
    out = tmp_path / "report.json"

    code = _emit(_report(), "json", str(out), "low", "high", classification="pii")

    shown = json.loads(out.read_text())
    assert [f["rule_id"] for r in shown["results"] for f in r["findings"]] == ["pii-email-in-logs"]
    assert shown["summary"]["total_findings"] == 1
    # The hidden high-severity findings still fail the build.
    assert code == 1


def test_sarif_carries_classification():
    sarif = aggregated_report_to_sarif(_report())
    run = sarif["runs"][0]
    # SARIF ids are "<tool>/<rule_id>".
    rules = {r["id"].split("/", 1)[1]: r for r in run["tool"]["driver"]["rules"]}
    results = {r["ruleId"].split("/", 1)[1]: r for r in run["results"]}

    assert "pii" in rules["pii-email-in-logs"]["properties"]["tags"]
    assert rules["pii-email-in-logs"]["properties"]["data_classification"] == "pii"
    assert results["hipaa-phi-in-logs"]["properties"]["data_classification"] == "phi"
    assert "data_classification" not in results["command-injection"]["properties"]
    assert "unset" not in rules["command-injection"]["properties"]["tags"]


def test_policy_suppression_refreshes_summary():
    policy = PolicyConfig(suppressions=[Suppression(rule_id="command-injection")])

    report = apply_policy(_report(), policy)

    assert report["summary"]["total_findings"] == 3
