"""Tests for local code review orchestration."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from argus.git_files import GitFilesError, build_review_tree
from argus.models import AggregatedReport, Finding, ScanResult, ScanType, Severity
from argus.tools.review import run_review


@pytest.mark.asyncio
async def test_run_review_empty_diff(tmp_path: Path) -> None:
    with patch(
        "argus.tools.review.list_changed_files",
        return_value=(tmp_path, []),
    ):
        report = await run_review(str(tmp_path))

    assert isinstance(report, AggregatedReport)
    assert report.results[0].metadata.get("file_count") == 0
    assert report.results[0].findings == []


@pytest.mark.asyncio
async def test_run_review_scans_changed_files(tmp_path: Path) -> None:
    changed = tmp_path / "leak.py"
    changed.write_text("password = 'hunter2'\n")
    staging_parent = tmp_path / "stage"
    staging_parent.mkdir()

    fake_secret = ScanResult(
        tool="detect-secrets",
        scan_type=ScanType.SECRETS,
        target="staging",
        findings=[
            Finding(
                title="Hardcoded password",
                severity=Severity.HIGH,
                scan_type=ScanType.SECRETS,
                tool="detect-secrets",
                file="PLACEHOLDER",
                line=1,
            )
        ],
    )

    async def _secrets(target: str, timeout: int = 300):
        staged = Path(target) / "leak.py"
        fake_secret.findings[0].file = str(staged)
        return [fake_secret]

    with (
        patch(
            "argus.tools.review.list_changed_files",
            return_value=(tmp_path, [changed]),
        ),
        patch("argus.tools.review.run_all_secrets", new=AsyncMock(side_effect=_secrets)),
        patch("argus.tools.review.run_all_sast", new=AsyncMock(return_value=[])),
        patch(
            "argus.tools.review.run_malware_scan",
            new=AsyncMock(
                return_value=ScanResult(
                    tool="argus-malware",
                    scan_type=ScanType.MALWARE,
                    target="staging",
                )
            ),
        ),
    ):
        report = await run_review(str(tmp_path), staging_parent=staging_parent)

    assert report.results[0].metadata.get("file_count") == 1
    assert "leak.py" in report.results[0].metadata.get("files", [])
    secret = next(r for r in report.results if r.tool == "detect-secrets")
    assert secret.findings[0].file == "leak.py"


@pytest.mark.asyncio
async def test_run_review_not_a_git_repo(tmp_path: Path) -> None:
    with patch(
        "argus.tools.review.list_changed_files",
        side_effect=GitFilesError("Not a git repository"),
    ):
        report = await run_review(str(tmp_path))

    assert report.results[0].tool_available is False
    assert report.results[0].errors


def test_build_review_tree_used_by_review(tmp_path: Path) -> None:
    """Smoke: staging helper copies files for review orchestration."""
    src = tmp_path / "a.py"
    src.write_text("x=1\n")
    stage = tmp_path / "stage"
    stage.mkdir()
    tree = build_review_tree([src], tmp_path, staging_parent=stage)
    try:
        assert (tree.root / "a.py").is_file()
    finally:
        tree.cleanup()
