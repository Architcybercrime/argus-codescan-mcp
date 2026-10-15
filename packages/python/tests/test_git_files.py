"""Tests for git changed-file listing and review staging."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from argus.git_files import (
    GitFilesError,
    build_review_tree,
    find_git_root,
    list_changed_files,
)


def test_find_git_root_success(tmp_path: Path) -> None:
    with patch("argus.git_files.subprocess.run") as run:
        run.return_value.returncode = 0
        run.return_value.stdout = f"{tmp_path}\n"
        run.return_value.stderr = ""
        assert find_git_root(tmp_path / "src") == tmp_path.resolve()


def test_find_git_root_not_a_repo(tmp_path: Path) -> None:
    with patch("argus.git_files.subprocess.run") as run:
        run.return_value.returncode = 128
        run.return_value.stdout = ""
        run.return_value.stderr = "fatal: not a git repository"
        with pytest.raises(GitFilesError, match="Not a git repository"):
            find_git_root(tmp_path)


def test_list_changed_files_vs_head(tmp_path: Path) -> None:
    changed = tmp_path / "app.py"
    changed.write_text("print('hi')\n")
    junk_dir = tmp_path / "node_modules" / "pkg"
    junk_dir.mkdir(parents=True)
    junk = junk_dir / "x.js"
    junk.write_text("x\n")

    def _fake_run(cmd, **kwargs):
        class R:
            returncode = 0
            stderr = ""
            stdout = ""

        if "rev-parse" in cmd:
            R.stdout = f"{tmp_path}\n"
        elif "diff" in cmd:
            R.stdout = "app.py\nnode_modules/pkg/x.js\n"
        elif "ls-files" in cmd:
            R.stdout = ""
        return R()

    with patch("argus.git_files.subprocess.run", side_effect=_fake_run):
        root, files = list_changed_files(tmp_path)

    assert root == tmp_path.resolve()
    assert changed.resolve() in files
    assert junk.resolve() not in files


def test_list_changed_files_staged_only(tmp_path: Path) -> None:
    staged = tmp_path / "staged.py"
    staged.write_text("x = 1\n")

    def _fake_run(cmd, **kwargs):
        class R:
            returncode = 0
            stderr = ""
            stdout = ""

        if "rev-parse" in cmd:
            R.stdout = f"{tmp_path}\n"
        elif "--cached" in cmd:
            R.stdout = "staged.py\n"
        return R()

    with patch("argus.git_files.subprocess.run", side_effect=_fake_run):
        _, files = list_changed_files(tmp_path, staged=True)

    assert staged.resolve() in files


def test_build_review_tree_and_remap(tmp_path: Path) -> None:
    src = tmp_path / "pkg" / "main.py"
    src.parent.mkdir()
    src.write_text("SECRET = 'x'\n")
    staging_parent = tmp_path / "stage"
    staging_parent.mkdir()
    tree = build_review_tree([src], tmp_path, staging_parent=staging_parent)
    try:
        staged = tree.root / "pkg" / "main.py"
        assert staged.is_file()
        assert tree.relative_files == ("pkg/main.py",)
        assert tree.remap_finding_path(str(staged)) == "pkg/main.py"
    finally:
        tree.cleanup()
