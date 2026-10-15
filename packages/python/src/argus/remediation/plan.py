"""Build read-only, severity-ordered remediation groups from scan reports."""

from __future__ import annotations

from typing import Any

from argus.models import Severity
from argus.remediation.secrets import remediation_to_dict

_SEVERITIES = [severity.value for severity in Severity]


def _text(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string")
    return value


def _position(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{field} must be a non-negative integer")
    return value


def _strings(value: Any, field: str) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ValueError(f"{field} must be an array of strings")
    return value


def build_fix_plan(report: dict[str, Any]) -> dict[str, Any]:
    """Group findings by scan type, tool and rule, with highest severity first.

    Input must be an AggregatedReport dictionary. Unknown severity strings sort
    last. No scanners, file access, network requests or automated fixes run here.
    """
    if not isinstance(report, dict) or not isinstance(report.get("results"), list):
        raise ValueError("report must be an object with a results array")
    target = _text(report.get("target", ""), "target")
    groups: dict[tuple[str, str, str], dict[str, Any]] = {}
    warnings: list[str] = []
    total = 0
    for result in report["results"]:
        if not isinstance(result, dict) or not isinstance(result.get("findings"), list):
            raise ValueError("each result must be an object with a findings array")
        tool = _text(result.get("tool", ""), "result.tool")
        scan_type = _text(result.get("scan_type", ""), "result.scan_type")
        errors = _strings(result.get("errors", []), "result.errors")
        if result.get("tool_available") is False:
            warnings.append(f"{tool or 'Scanner'} was unavailable; coverage may be incomplete.")
        warnings.extend(f"{tool or 'Scanner'}: {error}" for error in errors)
        for finding in result["findings"]:
            if not isinstance(finding, dict):
                raise ValueError("each finding must be an object")
            finding_tool = _text(finding.get("tool", tool), "finding.tool")
            finding_type = _text(finding.get("scan_type", scan_type), "finding.scan_type")
            rule = _text(finding.get("rule_id", ""), "finding.rule_id")
            title = _text(finding.get("title", ""), "finding.title")
            severity = _text(finding.get("severity", "unknown"), "finding.severity").lower()
            if severity not in _SEVERITIES:
                severity = Severity.UNKNOWN.value
            file = _text(finding.get("file", ""), "finding.file")
            line = _position(finding.get("line", 0), "finding.line")
            column = _position(finding.get("column", 0), "finding.column")
            guidance = _text(finding.get("fix_guidance", ""), "finding.fix_guidance")
            references = list(_strings(finding.get("references", []), "finding.references"))
            if finding_type == "secrets" and not guidance:
                remediation = remediation_to_dict(rule, title, finding_tool)
                guidance = remediation["fix_guidance"]
                references.extend(remediation["references"])
            # A missing rule ID falls back to title; different tools remain separate.
            key = (finding_type, finding_tool, rule or title)
            if key not in groups:
                groups[key] = {
                    "scan_type": finding_type,
                    "tool": finding_tool,
                    "rule_id": rule,
                    "title": title,
                    "severity": severity,
                    "finding_count": 0,
                    "locations": [],
                    "fix_guidance": [],
                    "references": [],
                }
            group = groups[key]
            if _SEVERITIES.index(severity) < _SEVERITIES.index(group["severity"]):
                group["severity"] = severity
            group["finding_count"] += 1
            group["locations"].append({"file": file, "line": line, "column": column})
            if guidance and guidance not in group["fix_guidance"]:
                group["fix_guidance"].append(guidance)
            for reference in references:
                if reference not in group["references"]:
                    group["references"].append(reference)
            total += 1

    ordered = sorted(
        groups.values(),
        key=lambda group: (
            _SEVERITIES.index(group["severity"]),
            group["scan_type"],
            group["tool"],
            group["rule_id"],
            group["title"],
        ),
    )
    for priority, group in enumerate(ordered, 1):
        group["priority"] = priority
        group["locations"].sort(key=lambda loc: (loc["file"], loc["line"], loc["column"]))
        group["fix_guidance"].sort()
        group["references"].sort()
    return {
        "target": target,
        "summary": {"total_findings": total, "fix_groups": len(ordered)},
        "groups": ordered,
        "warnings": warnings,
    }
