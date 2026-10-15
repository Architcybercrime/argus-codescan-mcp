"""Tests for static MCP resources and their public protocol representation."""

import json
import sys
from unittest.mock import patch

import jsonschema
import pytest

from argus.models import Finding, ScanType, Severity
from argus.resources import RESOURCE_DEFINITIONS, finding_schema, read_resource_json


def test_finding_schema_matches_serialised_model():
    schema = finding_schema()
    finding = Finding(
        title="Example",
        severity=Severity.HIGH,
        scan_type=ScanType.SAST,
        tool="semgrep",
        file="app.py",
        line=3,
    ).to_dict()
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.validate(finding, schema)
    assert set(schema["properties"]) == set(finding)
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate({**finding, "severity": "invented"}, schema)


def test_scan_types_match_model_and_registered_tools():
    data = json.loads(read_resource_json("argus://scan-types"))
    assert {item["id"] for item in data["scan_types"]} == {item.value for item in ScanType}


@pytest.mark.parametrize(
    "uri",
    [
        "argus://unknown",
        "file:///etc/passwd",
        "https://example.invalid/",
        "argus://scan-types?extra=1",
    ],
)
def test_unknown_uris_are_rejected(uri):
    with pytest.raises(ValueError, match="Unknown Argus resource"):
        read_resource_json(uri)


@pytest.mark.asyncio
async def test_advertised_resources_have_json_mime_types_and_no_scan_side_effects():
    from argus.server import list_resources, read_resource
    from pydantic import AnyUrl

    with patch("argus.server.run_all_sast", side_effect=AssertionError("Must not scan")):
        resources = await list_resources()
        assert len(resources) == 3
        assert len({str(resource.uri) for resource in resources}) == 3
        for resource in resources:
            assert resource.mimeType == "application/json"
            contents = await read_resource(AnyUrl(str(resource.uri)))
            assert contents[0].mime_type == "application/json"
            assert isinstance(json.loads(contents[0].content), dict)


@pytest.mark.asyncio
async def test_workflow_requests_match_registered_tool_schemas():
    from argus.server import list_tools

    tools = {tool.name: tool for tool in await list_tools()}
    workflows = json.loads(read_resource_json("argus://workflows"))["workflows"]
    for workflow in workflows:
        for request in workflow.get("requests", [workflow.get("request")]):
            jsonschema.validate(request["arguments"], tools[request["name"]].inputSchema)
    for scan_type in json.loads(read_resource_json("argus://scan-types"))["scan_types"]:
        assert scan_type["tool"] in tools


@pytest.mark.asyncio
async def test_stdio_client_lists_and_reads_resources_and_rejects_unknown_uri():
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
    from mcp.shared.exceptions import McpError
    from pydantic import AnyUrl

    params = StdioServerParameters(command=sys.executable, args=["-m", "argus.server"])
    async with stdio_client(params) as (read, write), ClientSession(read, write) as client:
        await client.initialize()
        resources = await client.list_resources()
        assert {str(resource.uri) for resource in resources.resources} == {
            item[0] for item in RESOURCE_DEFINITIONS
        }
        for resource in resources.resources:
            result = await client.read_resource(resource.uri)
            assert result.contents[0].mimeType == "application/json"
            json.loads(result.contents[0].text)
        with pytest.raises(McpError, match="Unknown Argus resource"):
            await client.read_resource(AnyUrl("argus://unknown"))
