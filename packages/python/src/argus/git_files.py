"""Resolve git-changed / staged files for local code review scans."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from argus.utils import SKIP_SCAN_DIRS


class GitFilesError(ValueError):
    """Raised when a git review path cannot be resolved."""


@dataclass(frozen=True)
class ReviewTree:
    """Temporary tree of changed files plus path remapping metadata."""

    root: Path
    repo_root: Path
    relative_files: tuple[str, ...]
    _tmpdir: tempfile.TemporaryDirectory[str]

    def cleanup(self) -> None:
        self._tmpdir.cleanup()

    def remap_finding_path(self, path: str) -> str:
        """Map a path under the staging tree back to a repo-relative path."""
        if not path:
            return path
        try:
            staging = Path(path).resolve()
            rel = staging.relative_to(self.root.resolve())
            return str(rel).replace("\\", "/")
        except (ValueError, OSError):
            # Already repo-relative or outside staging — leave unchanged.
            text = path.replace("\\", "/")
            root_s = str(self.root.resolve()).replace("\\", "/")
            if text.startswith(root_s.rstrip("/") + "/"):
                return text[len(root_s.rstrip("/")) + 1 :]
            return text


def find_git_root(start: str | Path) -> Path:
    """Return the git work-tree root containing ``start``."""
    path = Path(start).expanduser().resolve()
    if path.is_file():
        path = path.parent
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=path,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise GitFilesError(f"git is not available: {exc}") from exc
    if proc.returncode != 0 or not proc.stdout.strip():
        raise GitFilesError(f"Not a git repository: {path}")
    return Path(proc.stdout.strip()).resolve()


def _git_lines(repo_root: Path, *args: str) -> list[str]:
    proc = subprocess.run(
        ["git", *args],
        cwd=repo_root,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "git command failed").strip()
        raise GitFilesError(err)
    return [line.strip() for line in proc.stdout.splitlines() if line.strip()]


def _under_skip_dir(rel: Path) -> bool:
    return any(part in SKIP_SCAN_DIRS for part in rel.parts)


def list_changed_files(
    start: str | Path,
    *,
    staged: bool = False,
    base: str | None = None,
    include_untracked: bool = True,
) -> tuple[Path, list[Path]]:
    """List existing changed files under the git root for ``start``.

    Returns ``(repo_root, absolute_file_paths)``.
    """
    repo_root = find_git_root(start)
    names: list[str] = []

    if staged:
        names.extend(_git_lines(repo_root, "diff", "--cached", "--name-only", "--diff-filter=ACMR"))
    elif base:
        names.extend(
            _git_lines(repo_root, "diff", "--name-only", "--diff-filter=ACMR", f"{base}...HEAD")
        )
        # Also include uncommitted work on top of the branch tip.
        names.extend(_git_lines(repo_root, "diff", "--name-only", "--diff-filter=ACMR", "HEAD"))
        if include_untracked:
            names.extend(_git_lines(repo_root, "ls-files", "--others", "--exclude-standard"))
    else:
        names.extend(_git_lines(repo_root, "diff", "--name-only", "--diff-filter=ACMR", "HEAD"))
        if include_untracked:
            names.extend(_git_lines(repo_root, "ls-files", "--others", "--exclude-standard"))

    seen: set[str] = set()
    files: list[Path] = []
    for name in names:
        key = name.replace("\\", "/")
        if key in seen:
            continue
        seen.add(key)
        rel = Path(name)
        if _under_skip_dir(rel):
            continue
        abs_path = (repo_root / rel).resolve()
        try:
            abs_path.relative_to(repo_root)
        except ValueError:
            continue
        if abs_path.is_file():
            files.append(abs_path)

    files.sort(key=lambda p: str(p).lower())
    return repo_root, files


def build_review_tree(
    files: list[Path],
    repo_root: Path,
    *,
    staging_parent: Path | None = None,
) -> ReviewTree:
    """Copy changed files into a temporary tree preserving relative paths."""
    tmp = tempfile.TemporaryDirectory(
        prefix="argus-review-",
        dir=str(staging_parent) if staging_parent is not None else None,
    )
    root = Path(tmp.name)
    rels: list[str] = []
    for src in files:
        try:
            rel = src.resolve().relative_to(repo_root.resolve())
        except ValueError:
            continue
        dest = root / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dest)
        rels.append(str(rel).replace("\\", "/"))
    return ReviewTree(root=root, repo_root=repo_root, relative_files=tuple(rels), _tmpdir=tmp)
