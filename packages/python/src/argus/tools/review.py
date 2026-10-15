"""Local code review — scan git-changed / staged files only."""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Any

from argus.git_files import GitFilesError, ReviewTree, build_review_tree, list_changed_files
from argus.models import AggregatedReport, Finding, ScanResult, ScanType, Severity
from argus.tools.malware import run_malware_scan
from argus.tools.sast import run_all_sast
from argus.tools.secrets import run_all_secrets
from argus.utils import collect_scan_results

logger = logging.getLogger(__name__)


def _remap_results(results: list[ScanResult], tree: ReviewTree) -> list[ScanResult]:
    for result in results:
        result.target = str(tree.repo_root)
        for finding in result.findings:
            finding.file = tree.remap_finding_path(finding.file)
    return results


def _empty_review_result(repo_root: Path, *, reason: str) -> list[ScanResult]:
    return [
        ScanResult(
            tool="argus-review",
            scan_type=ScanType.SAST,
            target=str(repo_root),
            findings=[],
            errors=[],
            tool_available=True,
            metadata={"review": True, "message": reason, "files": [], "file_count": 0},
        )
    ]


async def run_review(
    target: str,
    *,
    staged: bool = False,
    base: str | None = None,
    timeout: int = 300,
    semgrep_config: str = "auto",
    staging_parent: Path | None = None,
) -> AggregatedReport:
    """Review git-changed files with secrets + SAST + malware scanners.

    Does not modify source files. Findings use repo-relative paths when possible.
    """
    try:
        repo_root, files = list_changed_files(target, staged=staged, base=base)
    except GitFilesError as exc:
        result = ScanResult(
            tool="argus-review",
            scan_type=ScanType.SAST,
            target=target,
            tool_available=False,
            errors=[str(exc)],
            metadata={"review": True},
        )
        return AggregatedReport(target=target, results=[result])

    if not files:
        mode = "staged" if staged else (f"vs {base}" if base else "vs HEAD")
        results = _empty_review_result(
            repo_root,
            reason=(
                f"No changed files to review ({mode}). "
                "Working tree matches the selected baseline."
            ),
        )
        return AggregatedReport(target=str(repo_root), results=results)

    tree = build_review_tree(files, repo_root, staging_parent=staging_parent)
    try:
        batches = await asyncio.gather(
            run_all_secrets(str(tree.root), timeout=timeout),
            run_all_sast(str(tree.root), semgrep_config=semgrep_config, timeout=timeout),
            run_malware_scan(str(tree.root)),
            return_exceptions=True,
        )
        results: list[ScanResult] = []
        for batch in batches:
            if isinstance(batch, list):
                results.extend(batch)
            elif isinstance(batch, ScanResult):
                results.append(batch)
            elif isinstance(batch, BaseException):
                logger.exception("Review scanner failed: %s", batch)
                results.append(
                    ScanResult(
                        tool="argus-review",
                        scan_type=ScanType.SAST,
                        target=str(repo_root),
                        tool_available=False,
                        errors=[f"{type(batch).__name__}: {batch}"],
                    )
                )

        results = _remap_results(collect_scan_results(results, label="Review"), tree)
        meta = {
            "review": True,
            "staged": staged,
            "base": base or "",
            "files": list(tree.relative_files),
            "file_count": len(tree.relative_files),
        }
        if results:
            results[0].metadata = {**(results[0].metadata or {}), **meta}
        else:
            results = [
                ScanResult(
                    tool="argus-review",
                    scan_type=ScanType.SAST,
                    target=str(repo_root),
                    findings=[
                        Finding(
                            title="Local review completed with no scanner results",
                            severity=Severity.INFO,
                            scan_type=ScanType.SAST,
                            tool="argus-review",
                            description="No scanner returned results for the changed-file set.",
                        )
                    ],
                    metadata=meta,
                )
            ]
        return AggregatedReport(target=str(repo_root), results=results)
    finally:
        tree.cleanup()


def review_summary_lines(report: AggregatedReport) -> list[str]:
    """Human-readable preamble for CLI stderr / MCP markdown."""
    meta: dict[str, Any] = {}
    for result in report.results:
        if result.metadata.get("review"):
            meta = result.metadata
            break
    files = meta.get("files") or []
    lines = [
        f"Local review target: {report.target}",
        f"Changed files scanned: {meta.get('file_count', len(files))}",
    ]
    if files:
        preview = ", ".join(files[:12])
        if len(files) > 12:
            preview += f", … (+{len(files) - 12} more)"
        lines.append(f"Files: {preview}")
    if meta.get("message"):
        lines.append(str(meta["message"]))
    return lines
