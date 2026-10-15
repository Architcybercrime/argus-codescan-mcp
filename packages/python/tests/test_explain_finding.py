"""Tests for finding explanations, remediation and MCP protocol calls."""

from copy import deepcopy
import json
import sys
from unittest.mock import patch

import pytest

from argus.models import Finding, ScanType, Severity
from argus.remediation.explain import explain_finding


def finding(scan_type="sast", **fields):
    return {
        "title": "Example scanner finding",
        "severity": "high",
        "scan_type": scan_type,
        "tool": "example-scanner",
        **fields,
    }


@pytest.mark.parametrize("scan_type", [item.value for item in ScanType])
def test_explains_all_supported_categories_without_external_calls(scan_type):
    source = finding(scan_type, description="Reported context.", fix_guidance="Existing guidance.")
    original = deepcopy(source)
    result = explain_finding(source)
    assert result["finding"]["scan_type"] == scan_type
    assert result["explanation"] == "Reported context."
    assert result["fix_guidance"] == "Existing guidance."
    assert "Review the supplied scanner finding" in result["review_prompt"]
    assert "code_snippet" not in result
    assert source == original


@pytest.mark.parametrize(
    "cwe, expected",
    [
        (79, ["CWE-79"]),
        ("79", ["CWE-79"]),
        ("CWE-79: Cross-site scripting", ["CWE-79"]),
        ("['CWE-79', 'CWE-89', 'CWE-79']", ["CWE-79", "CWE-89"]),
        ("", []),
        ("Not supplied", []),
        (0, []),
        ("CWE-0", []),
    ],
)
def test_cwe_links_use_scanner_identifiers_without_guessing(cwe, expected):
    result = explain_finding(finding(cwe=cwe))
    assert result["cwe_ids"] == expected
    for identifier in expected:
        assert (
            f"https://cwe.mitre.org/data/definitions/{identifier[4:]}.html" in result["references"]
        )


def test_secret_rotation_checklist_is_present_even_with_existing_guidance():
    result = explain_finding(
        finding("secrets", rule_id="aws-access-key", fix_guidance="Local advice.")
    )
    assert result["fix_guidance"] == "Local advice."
    assert any("IAM" in step for step in result["rotation_checklist"])
    assert result["references"]


def test_unknown_secret_uses_generic_rotation_checklist():
    result = explain_finding(finding("secrets", rule_id="unknown-detector"))
    assert any("rotate" in step.lower() for step in result["rotation_checklist"])
    assert result["fix_guidance"]


def test_snippet_is_caller_supplied_and_internal_payload_is_excluded():
    data = finding(file="/does/not/exist.py", raw={"internal": "not-for-explanation"})
    with patch("builtins.open", side_effect=AssertionError("Must not read files")):
        result = explain_finding(data, "example(value)")
    assert result["code_snippet"] == "example(value)"
    assert "not-for-explanation" not in json.dumps(result)
    prompt_data = json.loads(result["review_prompt"].split("\n\n", 1)[1])
    assert prompt_data["code_snippet"] == "example(value)"


def test_accepts_actual_finding_serialisation_and_keeps_advisory_references():
    source = Finding(
        title="Dependency advisory",
        severity=Severity.HIGH,
        scan_type=ScanType.SCA,
        tool="pip-audit",
        cve="CVE-2026-12345",
        fix_guidance="Upgrade to the fixed version.",
        references=["https://example.invalid/advisory"],
    ).to_dict()
    result = explain_finding(source)
    assert result["finding"]["cve"] == "CVE-2026-12345"
    assert result["references"] == ["https://example.invalid/advisory"]


def test_missing_guidance_uses_category_review_steps_without_claiming_a_fix():
    result = explain_finding(finding("iac"))
    assert "deployment context" in result["fix_guidance"]
    assert result["rotation_checklist"] == []


@pytest.mark.parametrize(
    "fields",
    [
        {"title": ""},
        {"tool": " "},
        {"severity": "invented"},
        {"scan_type": "unknown"},
        {"description": None},
        {"line": True},
        {"line": -1},
        {"column": "2"},
        {"references": "url"},
        {"references": [None]},
        {"cwe": []},
        {"cwe": True},
    ],
)
def test_rejects_invalid_fields(fields):
    with pytest.raises(ValueError):
        explain_finding(finding(**fields))


@pytest.mark.parametrize("data", [None, [], "finding", {}])
def test_rejects_invalid_finding_objects(data):
    with pytest.raises(ValueError):
        explain_finding(data)


def test_rejects_non_text_snippets():
    with pytest.raises(ValueError, match="code_snippet"):
        explain_finding(finding(), 123)


@pytest.mark.asyncio
async def test_dispatch_is_read_only_and_does_not_upload_or_scan():
    from argus.server import call_tool

    with (
        patch("argus.server.run_all_sast", side_effect=AssertionError("Must not scan")),
        patch("argus.server.upload_scan_report", side_effect=AssertionError("Must not upload")),
        patch("argus.server.apply_finding_fix", side_effect=AssertionError("Must not apply")),
    ):
        result = await call_tool("explain_finding", {"finding": finding()})
    assert json.loads(result[0].text)["finding"]["title"] == "Example scanner finding"


@pytest.mark.asyncio
async def test_dispatch_returns_validation_message_for_missing_finding():
    from argus.server import call_tool

    result = await call_tool("explain_finding", {})
    assert result[0].text.startswith("Invalid finding:")


@pytest.mark.asyncio
async def test_stdio_client_discovers_tool_and_explains_secret_with_snippet():
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    params = StdioServerParameters(command=sys.executable, args=["-m", "argus.server"])
    async with stdio_client(params) as (read, write), ClientSession(read, write) as client:
        await client.initialize()
        tools = await client.list_tools()
        assert any(tool.name == "explain_finding" for tool in tools.tools)
        result = await client.call_tool(
            "explain_finding",
            {
                "finding": finding("secrets", rule_id="github"),
                "code_snippet": "token = placeholder",
            },
        )
        assert not result.isError
        explanation = json.loads(result.content[0].text)
        assert explanation["rotation_checklist"]
        assert explanation["code_snippet"] == "token = placeholder"
