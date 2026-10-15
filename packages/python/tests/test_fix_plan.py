"""Tests for read-only remediation grouping and MCP dispatch."""

from copy import deepcopy
import json
import sys
from unittest.mock import patch

import pytest

from argus.models import AggregatedReport, Finding, ScanResult, ScanType, Severity
from argus.remediation.plan import build_fix_plan


def report(*findings: dict) -> dict:
    return {
        "target": "/project",
        "results": [
            {"tool": "semgrep", "scan_type": "sast", "findings": list(findings)},
        ],
    }


def finding(rule: str = "sql-injection", severity: str = "high", **kwargs) -> dict:
    return {"rule_id": rule, "severity": severity, "title": rule, **kwargs}


def test_groups_rules_and_preserves_occurrence_locations_and_guidance():
    data = report(
        finding(
            file="b.py",
            line=12,
            fix_guidance="Use parameters.",
            references=["https://example.test/sql"],
        ),
        finding(
            file="a.py",
            line=2,
            fix_guidance="Use parameters.",
            references=["https://example.test/sql"],
        ),
        finding("xss", file="view.py"),
    )
    original = deepcopy(data)
    plan = build_fix_plan(data)
    assert plan["summary"] == {"total_findings": 3, "fix_groups": 2}
    group = plan["groups"][0]
    assert group["finding_count"] == 2
    assert group["locations"] == [
        {"file": "a.py", "line": 2, "column": 0},
        {"file": "b.py", "line": 12, "column": 0},
    ]
    assert group["fix_guidance"] == ["Use parameters."]
    assert group["references"] == ["https://example.test/sql"]
    assert data == original


def test_priority_uses_highest_group_severity_and_unknown_sorts_last():
    plan = build_fix_plan(
        report(
            finding("low", "low"),
            finding("mixed", "info"),
            finding("mixed", "critical"),
            finding("medium", "medium"),
            finding("unknown", "custom"),
            finding("high", "HIGH"),
        )
    )
    assert [group["severity"] for group in plan["groups"]] == [
        "critical",
        "high",
        "medium",
        "low",
        "unknown",
    ]
    assert [group["priority"] for group in plan["groups"]] == [1, 2, 3, 4, 5]
    assert plan["groups"][0]["finding_count"] == 2


def test_same_rule_from_different_scanners_or_scan_types_stays_separate():
    data = report(finding())
    data["results"].extend(
        [
            {"tool": "bandit", "scan_type": "sast", "findings": [finding()]},
            {"tool": "semgrep", "scan_type": "iac", "findings": [finding()]},
        ]
    )
    assert build_fix_plan(data)["summary"]["fix_groups"] == 3


def test_missing_rule_falls_back_to_title_and_order_is_stable():
    items = [finding("", title="B"), finding("", title="A"), finding("", title="A")]
    forward = build_fix_plan(report(*items))
    backward = build_fix_plan(report(*reversed(items)))
    assert forward == backward
    assert [group["title"] for group in forward["groups"]] == ["A", "B"]
    assert forward["groups"][0]["finding_count"] == 2


def test_secret_findings_get_existing_rotation_guidance():
    plan = build_fix_plan(report(finding("aws-access-key", scan_type="secrets")))
    assert "IAM" in plan["groups"][0]["fix_guidance"][0]
    assert plan["groups"][0]["references"]


def test_existing_guidance_is_preserved_without_generated_replacement():
    plan = build_fix_plan(report(finding(scan_type="secrets", fix_guidance="Custom rotation.")))
    assert plan["groups"][0]["fix_guidance"] == ["Custom rotation."]


def test_empty_report_retains_incomplete_scan_warnings():
    data = report()
    data["results"][0].update(tool_available=False, errors=["Tool timed out."])
    plan = build_fix_plan(data)
    assert plan["summary"] == {"total_findings": 0, "fix_groups": 0}
    assert plan["groups"] == []
    assert any("unavailable" in warning for warning in plan["warnings"])
    assert "semgrep: Tool timed out." in plan["warnings"]


def test_accepts_actual_aggregated_report_serialization():
    data = AggregatedReport(
        target="/project",
        results=[
            ScanResult(
                tool="bandit",
                scan_type=ScanType.SAST,
                target="/project",
                findings=[
                    Finding(
                        title="Injection",
                        severity=Severity.HIGH,
                        scan_type=ScanType.SAST,
                        tool="bandit",
                        file="app.py",
                        line=4,
                    ),
                ],
            ),
        ],
    ).to_dict()
    assert build_fix_plan(data)["summary"]["total_findings"] == 1


@pytest.mark.parametrize(
    "data",
    [
        None,
        [],
        {},
        {"results": None},
        {"results": [None]},
        {"results": [{"findings": {}}]},
        {"results": [{"findings": [None]}]},
    ],
)
def test_rejects_invalid_report_shapes(data):
    with pytest.raises(ValueError):
        build_fix_plan(data)


@pytest.mark.parametrize(
    "fields",
    [
        {"severity": 3},
        {"file": None},
        {"line": -1},
        {"line": True},
        {"column": "4"},
        {"references": "url"},
        {"references": [None]},
        {"fix_guidance": {}},
    ],
)
def test_rejects_invalid_finding_fields(fields):
    with pytest.raises(ValueError):
        build_fix_plan(report(finding(**fields)))


@pytest.mark.asyncio
async def test_mcp_dispatch_returns_plan_without_scanning_or_uploading():
    from argus.server import call_tool

    with (
        patch("argus.server.run_all_sast", side_effect=AssertionError("Must not scan")),
        patch("argus.server.upload_scan_report", side_effect=AssertionError("Must not upload")),
        patch("argus.server.apply_finding_fix", side_effect=AssertionError("Must not fix")),
    ):
        output = await call_tool(
            "get_fix_plan", {"scan_result_json": json.dumps(report(finding()))}
        )
    assert json.loads(output[0].text)["groups"][0]["rule_id"] == "sql-injection"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "args",
    [
        {},
        {"scan_result_json": 1},
        {"scan_result_json": "{"},
        {"scan_result_json": "[]"},
        {"scan_result_json": "{}"},
    ],
)
async def test_mcp_dispatch_rejects_invalid_inputs(args):
    from argus.server import call_tool

    output = await call_tool("get_fix_plan", args)
    assert output[0].text.startswith("Invalid")


@pytest.mark.asyncio
async def test_mcp_registration_exposes_required_report_parameter():
    from argus.server import list_tools

    tools = await list_tools()
    tool = next(tool for tool in tools if tool.name == "get_fix_plan")
    assert tool.inputSchema["required"] == ["scan_result_json"]
    assert "read-only" in tool.description


@pytest.mark.asyncio
async def test_stdio_client_can_discover_and_call_fix_plan():
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    parameters = StdioServerParameters(command=sys.executable, args=["-m", "argus.server"])
    async with stdio_client(parameters) as (read, write), ClientSession(read, write) as client:
        await client.initialize()
        tools = await client.list_tools()
        assert any(tool.name == "get_fix_plan" for tool in tools.tools)
        output = await client.call_tool(
            "get_fix_plan", {"scan_result_json": json.dumps(report(finding()))}
        )
        assert not output.isError
        plan = json.loads(output.content[0].text)
        assert plan["summary"]["total_findings"] == 1
