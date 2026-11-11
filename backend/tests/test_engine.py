"""
Unit Tests for CloudSentinel Scanner Engine and Credential Protection.
Tests credential redaction, read-only session verification, and check aggregation.
"""
from unittest.mock import MagicMock
import pytest
from backend.scanner.engine import CloudSentinelEngine, CredentialProtector
from backend.scanner.models import Finding, Severity, Status, Remediation


def test_credential_protector_redaction():
    leak_sample = (
        "Config: aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY and "
        "SecretAccessKey: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY and "
        '{"aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"} and '
        "aws_session_token = FwoGZXIvYXdzEEXAMPLETOKEN and "
        "key ID AKIAIOSFODNN7EXAMPLE"
    )
    redacted = CredentialProtector.redact(leak_sample)
    assert "wJalrXUtn" not in redacted
    assert "FwoGZXIvYXdz" not in redacted
    assert "AKIAIOSFODNN7EXAMPLE" not in redacted
    assert "[REDACTED]" in redacted


def test_engine_verify_read_only_with_missing_credentials():
    mock_session = MagicMock()
    mock_session.get_credentials.return_value = None

    engine = CloudSentinelEngine(session=mock_session)
    result = engine.verify_read_only_access()

    assert result["valid"] is False
    assert result["read_only"] is True
    assert "No AWS credentials" in result["error"]


def test_engine_verify_read_only_with_valid_credentials():
    mock_session = MagicMock()
    mock_session.get_credentials.return_value = MagicMock()
    mock_sts = MagicMock()
    mock_sts.get_caller_identity.return_value = {
        "Account": "123456789012",
        "Arn": "arn:aws:iam::123456789012:role/ScannerRole",
        "UserId": "AROAEXAMPLE",
    }
    mock_session.client.return_value = mock_sts

    engine = CloudSentinelEngine(session=mock_session)
    result = engine.verify_read_only_access()

    assert result["valid"] is True
    assert result["account_masked"] == "1234****9012"
    assert result["arn"] == "arn:aws:iam::1234****9012:role/ScannerRole"


def test_engine_run_all_checks_aggregates_findings():
    mock_session = MagicMock()
    engine = CloudSentinelEngine(session=mock_session)

    # Mock checks to return deterministic findings
    dummy_finding = Finding(
        check_id="test_check",
        check_title="Test Check Title",
        service="s3",
        severity=Severity.HIGH,
        status=Status.PASS,
        status_extended="Test passed cleanly",
        resource_id="res-1",
        resource_arn="arn:aws:s3:::res-1",
        region="us-east-1",
        remediation=Remediation("desc", "rec", "cli", "tf"),
    )

    for check in engine.checks:
        check.execute = MagicMock(return_value=[dummy_finding])

    result = engine.run_all_checks()

    assert "summary" in result
    assert "findings" in result
    assert "score_explanation" in result
    assert result["read_only_verified"] is True
    assert result["summary"]["passed_checks"] == len(engine.checks)
    assert result["summary"]["security_score"] == 100.0
