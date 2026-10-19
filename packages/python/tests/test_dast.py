"""Tests for DAST runner error handling."""

import asyncio

from argus.tools import dast


def _no_zap(monkeypatch, *, in_container):
    monkeypatch.setattr(dast, "is_tool_available", lambda name: False)
    monkeypatch.setattr(dast, "_find_zap_cli", lambda: None)
    monkeypatch.setattr(dast, "running_in_container", lambda: in_container)


def test_zap_missing_in_container_explains_nested_docker(monkeypatch):
    _no_zap(monkeypatch, in_container=True)

    result = asyncio.run(dast.run_zap_baseline("http://localhost:3000"))

    assert result.tool_available is False
    assert result.errors[-1] == dast.ZAP_IN_CONTAINER_HELP
    assert "docker.sock" in result.errors[-1]


def test_zap_missing_on_host_lists_install_options(monkeypatch):
    _no_zap(monkeypatch, in_container=False)

    result = asyncio.run(dast.run_zap_baseline("http://localhost:3000"))

    assert result.tool_available is False
    assert result.errors[-1].startswith("OWASP ZAP is not available")


def test_zap_docker_without_daemon_in_container(monkeypatch):
    async def fake_run_command(cmd, timeout):
        return 1, "", "Cannot connect to the Docker daemon at unix:///var/run/docker.sock."

    monkeypatch.setattr(dast, "is_tool_available", lambda name: name == "docker")
    monkeypatch.setattr(dast, "run_command", fake_run_command)
    monkeypatch.setattr(dast, "running_in_container", lambda: True)

    result = asyncio.run(dast.run_zap_baseline("http://localhost:3000"))

    assert result.errors == [dast.ZAP_IN_CONTAINER_HELP]
