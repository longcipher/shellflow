"""Unit tests for doctor module."""

from __future__ import annotations

from shellflow.doctor import run_doctor


def test_doctor_command():
    result = run_doctor()
    assert "SSH connections" in result
    assert "Configuration" in result
