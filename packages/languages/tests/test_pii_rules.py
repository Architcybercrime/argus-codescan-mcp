"""Tests for PII detection static rules."""

from pathlib import Path

from argus_languages.rules_loader import load_rules_from_files
from argus_languages.scanner import scan_path


def _scan_pii(path: Path):
    return scan_path(path, rules=load_rules_from_files(("pii.yaml",)))


def test_pii_email_in_logs_fstring(tmp_path: Path):
    f = tmp_path / "auth.py"
    f.write_text('logger.info(f"User signed in with email: {email}")\n')
    result = _scan_pii(f)
    ids = {x.rule_id for x in result.findings}
    assert "pii-email-in-logs" in ids


def test_pii_email_in_logs_attribute(tmp_path: Path):
    f = tmp_path / "service.py"
    f.write_text('log.debug(user.email)\n')
    result = _scan_pii(f)
    ids = {x.rule_id for x in result.findings}
    assert "pii-email-in-logs" in ids


def test_clean_logger_no_pii(tmp_path: Path):
    f = tmp_path / "server.py"
    f.write_text('logger.info("Server started successfully on port 8080")\n')
    result = _scan_pii(f)
    assert len(result.findings) == 0
