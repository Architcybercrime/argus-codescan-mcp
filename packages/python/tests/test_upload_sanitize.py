"""Cloud upload must not send PII or git credentials to the dashboard."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any
from unittest.mock import patch

import pytest

from argus.cloud_upload import (
    MAX_UPLOAD_MESSAGE_CHARS,
    redact_pii,
    sanitize_for_upload,
    strip_url_credentials,
    upload_scan_report,
)

PII_MESSAGE = "Customer jane.doe@example.com with SSN 123-45-6789 paid with 4111 1111 1111 1111"


def _report(description: str) -> dict[str, Any]:
    return {
        "target": "/tmp/project",
        "results": [
            {
                "tool": "semgrep",
                "findings": [
                    {
                        "rule_id": "pii-in-logs",
                        "title": "PII logged for ops@internal.example.org",
                        "severity": "medium",
                        "file": "app.py",
                        "line": 3,
                        "description": description,
                    }
                ],
            }
        ],
    }


def test_redact_pii_patterns():
    text, count = redact_pii(PII_MESSAGE)

    assert text == ("Customer [REDACTED_EMAIL] with SSN [REDACTED_SSN] paid with [REDACTED_CARD]")
    assert count == 3


def test_redact_pii_keeps_non_pii():
    for text in (
        "requests@2.31.0: vulnerable to CVE-2024-35195",
        "@types/node is outdated",
        "order id 1234567890123",  # 13 digits, fails Luhn
        "Use of assert detected",
    ):
        assert redact_pii(text) == (text, 0)


def test_strip_url_credentials():
    assert (
        strip_url_credentials("https://user:ghp_secret@github.com/org/repo.git")
        == "https://github.com/org/repo.git"
    )
    assert strip_url_credentials("https://github.com/org/repo.git") == (
        "https://github.com/org/repo.git"
    )
    assert strip_url_credentials("git@github.com:org/repo.git") == "git@github.com:org/repo.git"
    assert strip_url_credentials("") == ""


def test_sanitize_truncates_long_messages():
    payload = {"findings": [{"title": "t", "message": "x" * (MAX_UPLOAD_MESSAGE_CHARS + 50)}]}

    clean, count = sanitize_for_upload(payload)

    assert count == 0
    assert len(clean["findings"][0]["message"]) == MAX_UPLOAD_MESSAGE_CHARS + 1
    assert len(payload["findings"][0]["message"]) == MAX_UPLOAD_MESSAGE_CHARS + 50


class _Capture(BaseHTTPRequestHandler):
    bodies: list[dict[str, Any]] = []

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", 0))
        _Capture.bodies.append(json.loads(self.rfile.read(length)))
        self.send_response(201)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"id": "run-1"}')

    def log_message(self, *args: Any) -> None:
        pass


@pytest.fixture
def mock_dashboard(monkeypatch):
    _Capture.bodies = []
    server = HTTPServer(("127.0.0.1", 0), _Capture)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setenv("ARGUS_API_KEY", "arg_test")
    monkeypatch.setenv("ARGUS_API_URL", f"http://127.0.0.1:{server.server_port}/v1")
    monkeypatch.delenv("ARGUS_UPLOAD_SCRIPT", raising=False)
    yield _Capture.bodies
    server.shutdown()


def _git_meta() -> Any:
    return patch(
        "argus.cloud_upload.get_git_metadata",
        return_value={"repo": "https://github.com/org/repo.git", "branch": "main", "commit": "c"},
    )


@pytest.mark.asyncio
async def test_upload_payload_redacted_by_default(mock_dashboard, monkeypatch):
    monkeypatch.delenv("ARGUS_UPLOAD_REDACT", raising=False)

    with _git_meta():
        status = await upload_scan_report(_report(PII_MESSAGE), duration_sec=1.0)

    assert status == "uploaded (id: run-1)"
    sent = json.dumps(mock_dashboard[0])
    for raw in ("jane.doe@example.com", "123-45-6789", "4111 1111 1111 1111", "ops@internal"):
        assert raw not in sent
    assert mock_dashboard[0]["findings"][0]["ruleId"] == "pii-in-logs"


@pytest.mark.asyncio
async def test_upload_redaction_can_be_disabled(mock_dashboard, monkeypatch):
    monkeypatch.setenv("ARGUS_UPLOAD_REDACT", "0")

    with _git_meta():
        await upload_scan_report(_report(PII_MESSAGE), duration_sec=1.0)

    assert mock_dashboard[0]["findings"][0]["message"] == PII_MESSAGE
