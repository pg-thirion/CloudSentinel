"""
Unit and integration tests for CloudSentinel S3 Public Access Detection Engine.
Validates:
1. Vulnerable bucket configurations (Public policy, public ACL, disabled/incomplete Public Access Block) -> Status.FAIL
2. Safe / hardened bucket configurations (Full Public Access Block, private ACL, restricted policy) -> Status.PASS
3. Permission failures (AccessDenied on list_buckets, get_public_access_block, get_bucket_policy, get_bucket_acl) -> Status.ACCESS_DENIED
"""
import json
from unittest.mock import MagicMock
import boto3
from botocore.stub import Stubber
from moto import mock_aws
import pytest

from backend.scanner.checks.s3_public_access import S3PublicAccessCheck
from backend.scanner.models import Status, Severity


@pytest.fixture
def check():
    return S3PublicAccessCheck()


@pytest.fixture
def aws_credentials(monkeypatch):
    """Mocked AWS Credentials for moto."""
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")


# ==============================================================================
# TEST CASE 1: Vulnerable Configurations (FAIL)
# ==============================================================================

@mock_aws
def test_vulnerable_bucket_missing_public_access_block(aws_credentials, check):
    """Test Case 1a: Bucket created without any Public Access Block configured fails."""
    session = boto3.Session(region_name="us-east-1")
    s3 = session.client("s3", region_name="us-east-1")
    bucket_name = "test-no-pab-bucket"
    s3.create_bucket(Bucket=bucket_name)

    findings = check.run_check(session)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.status == Status.FAIL
    assert finding.severity == Severity.CRITICAL
    assert finding.resource_id == bucket_name
    assert finding.resource_arn == f"arn:aws:s3:::{bucket_name}"
    assert "Public Access Block is not configured" in finding.status_extended
    assert "aws s3api put-public-access-block" in finding.remediation.cli_command
    assert "aws_s3_bucket_public_access_block" in finding.remediation.terraform_fix


@mock_aws
def test_vulnerable_bucket_partial_public_access_block(aws_credentials, check):
    """Test Case 1b: Bucket with partial Public Access Block settings fails."""
    session = boto3.Session(region_name="us-east-1")
    s3 = session.client("s3", region_name="us-east-1")
    bucket_name = "test-partial-pab-bucket"
    s3.create_bucket(Bucket=bucket_name)
    s3.put_public_access_block(
        Bucket=bucket_name,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": False,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": False,
            "RestrictPublicBuckets": True,
        },
    )

    findings = check.run_check(session)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.status == Status.FAIL
    assert "BlockPublicAcls=False" in finding.status_extended
    assert "BlockPublicPolicy=False" in finding.status_extended


@mock_aws
def test_vulnerable_bucket_public_policy_wildcard_string(aws_credentials, check):
    """Test Case 1c: Bucket with wildcard string Principal without restrictive condition fails."""
    session = boto3.Session(region_name="us-east-1")
    s3 = session.client("s3", region_name="us-east-1")
    bucket_name = "test-public-policy-str-bucket"
    s3.create_bucket(Bucket=bucket_name)
    s3.put_public_access_block(
        Bucket=bucket_name,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )
    s3.put_bucket_policy(
        Bucket=bucket_name,
        Policy=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Sid": "AllowPublicRead",
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": f"arn:aws:s3:::{bucket_name}/*",
            }],
        }),
    )

    findings = check.run_check(session)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.status == Status.FAIL
    assert "Public Bucket Policy allows wildcard access in statements: AllowPublicRead" in finding.status_extended


@mock_aws
def test_vulnerable_bucket_public_policy_wildcard_dict(aws_credentials, check):
    """Test Case 1d: Bucket with wildcard dict Principal: {'AWS': '*'} fails."""
    session = boto3.Session(region_name="us-east-1")
    s3 = session.client("s3", region_name="us-east-1")
    bucket_name = "test-public-policy-dict-bucket"
    s3.create_bucket(Bucket=bucket_name)
    s3.put_public_access_block(
        Bucket=bucket_name,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )
    s3.put_bucket_policy(
        Bucket=bucket_name,
        Policy=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Sid": "AllowWildcardAwsPrincipal",
                "Effect": "Allow",
                "Principal": {"AWS": "*"},
                "Action": "s3:GetObject",
                "Resource": f"arn:aws:s3:::{bucket_name}/*",
            }],
        }),
    )

    findings = check.run_check(session)

    assert len(findings) == 1
    assert findings[0].status == Status.FAIL
    assert "AllowWildcardAwsPrincipal" in findings[0].status_extended


@mock_aws
def test_vulnerable_bucket_public_policy_wildcard_list(aws_credentials, check):
    """Test Case 1e: Bucket with wildcard principal list: {'AWS': ['arn:...', '*']} fails."""
    session = boto3.Session(region_name="us-east-1")
    s3 = session.client("s3", region_name="us-east-1")
    bucket_name = "test-public-policy-list-bucket"
    s3.create_bucket(Bucket=bucket_name)
    s3.put_public_access_block(
        Bucket=bucket_name,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )
    s3.put_bucket_policy(
        Bucket=bucket_name,
        Policy=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Sid": "AllowWildcardInList",
                "Effect": "Allow",
                "Principal": {"AWS": ["arn:aws:iam::123456789012:root", "*"]},
                "Action": "s3:GetObject",
                "Resource": f"arn:aws:s3:::{bucket_name}/*",
            }],
        }),
    )

    findings = check.run_check(session)

    assert len(findings) == 1
    assert findings[0].status == Status.FAIL
    assert "AllowWildcardInList" in findings[0].status_extended


@mock_aws
def test_vulnerable_bucket_public_policy_non_restrictive_condition(aws_credentials, check):
    """Test Case 1f: Bucket with wildcard principal and non-restrictive condition (e.g. SecureTransport) fails."""
    session = boto3.Session(region_name="us-east-1")
    s3 = session.client("s3", region_name="us-east-1")
    bucket_name = "test-non-restrictive-condition-bucket"
    s3.create_bucket(Bucket=bucket_name)
    s3.put_public_access_block(
        Bucket=bucket_name,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )
    s3.put_bucket_policy(
        Bucket=bucket_name,
        Policy=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Sid": "TlsOnlyPublicAccess",
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": f"arn:aws:s3:::{bucket_name}/*",
                "Condition": {
                    "Bool": {
                        "aws:SecureTransport": "true"
                    }
                },
            }],
        }),
    )

    findings = check.run_check(session)

    assert len(findings) == 1
    assert findings[0].status == Status.FAIL
    assert "TlsOnlyPublicAccess" in findings[0].status_extended


@mock_aws
def test_vulnerable_bucket_public_policy_negative_operator_string_not_equals(aws_credentials, check):
    """Test Case 1g: Bucket with Principal '*' and inverted operator StringNotEquals fails (critic gap fix)."""
    session = boto3.Session(region_name="us-east-1")
    s3 = session.client("s3", region_name="us-east-1")
    bucket_name = "test-string-not-equals-bucket"
    s3.create_bucket(Bucket=bucket_name)
    s3.put_public_access_block(
        Bucket=bucket_name,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )
    # StringNotEquals in Allow statement allows every account EXCEPT 123456789012 (vulnerable / public)
    s3.put_bucket_policy(
        Bucket=bucket_name,
        Policy=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Sid": "AllowWorldExceptOneAccount",
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": f"arn:aws:s3:::{bucket_name}/*",
                "Condition": {
                    "StringNotEquals": {
                        "aws:PrincipalAccount": "123456789012"
                    }
                },
            }],
        }),
    )

    findings = check.run_check(session)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.status == Status.FAIL
    assert "AllowWorldExceptOneAccount" in finding.status_extended


@mock_aws
def test_vulnerable_bucket_public_policy_negative_operator_not_ip_address(aws_credentials, check):
    """Test Case 1h: Bucket with Principal '*' and inverted operator NotIpAddress fails."""
    session = boto3.Session(region_name="us-east-1")
    s3 = session.client("s3", region_name="us-east-1")
    bucket_name = "test-not-ip-address-bucket"
    s3.create_bucket(Bucket=bucket_name)
    s3.put_public_access_block(
        Bucket=bucket_name,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )
    s3.put_bucket_policy(
        Bucket=bucket_name,
        Policy=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Sid": "AllowWorldExceptInternalSubnet",
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": f"arn:aws:s3:::{bucket_name}/*",
                "Condition": {
                    "NotIpAddress": {
                        "aws:SourceIp": "10.0.0.0/8"
                    }
                },
            }],
        }),
    )

    findings = check.run_check(session)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.status == Status.FAIL
    assert "AllowWorldExceptInternalSubnet" in finding.status_extended


@mock_aws
def test_vulnerable_bucket_public_policy_negative_operator_if_exists(aws_credentials, check):
    """Test Case 1i: Bucket with Principal '*' and StringNotEqualsIfExists fails."""
    session = boto3.Session(region_name="us-east-1")
    s3 = session.client("s3", region_name="us-east-1")
    bucket_name = "test-not-equals-if-exists-bucket"
    s3.create_bucket(Bucket=bucket_name)
    s3.put_public_access_block(
        Bucket=bucket_name,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )
    s3.put_bucket_policy(
        Bucket=bucket_name,
        Policy=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Sid": "AllowWorldWithNotIfExists",
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": f"arn:aws:s3:::{bucket_name}/*",
                "Condition": {
                    "StringNotEqualsIfExists": {
                        "aws:PrincipalArn": "arn:aws:iam::123456789012:role/SpecificRole"
                    }
                },
            }],
        }),
    )

    findings = check.run_check(session)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.status == Status.FAIL
    assert "AllowWorldWithNotIfExists" in finding.status_extended


@mock_aws
def test_vulnerable_bucket_public_acl_all_users(aws_credentials, check):
    """Test Case 1g: Bucket with ACL grant to AllUsers fails."""
    session = boto3.Session(region_name="us-east-1")
    s3 = session.client("s3", region_name="us-east-1")
    bucket_name = "test-public-acl-allusers-bucket"
    s3.create_bucket(Bucket=bucket_name)
    s3.put_public_access_block(
        Bucket=bucket_name,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )
    s3.put_bucket_acl(Bucket=bucket_name, ACL="public-read")

    findings = check.run_check(session)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.status == Status.FAIL
    assert "Public ACL grants detected: AllUsers (READ)" in finding.status_extended


@mock_aws
def test_vulnerable_bucket_public_acl_authenticated_users(aws_credentials, check):
    """Test Case 1h: Bucket with ACL grant to AuthenticatedUsers fails."""
    session = boto3.Session(region_name="us-east-1")
    s3 = session.client("s3", region_name="us-east-1")
    bucket_name = "test-public-acl-authusers-bucket"
    s3.create_bucket(Bucket=bucket_name)
    s3.put_public_access_block(
        Bucket=bucket_name,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )
    s3.put_bucket_acl(Bucket=bucket_name, ACL="authenticated-read")

    findings = check.run_check(session)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.status == Status.FAIL
    assert "AuthenticatedUsers (READ)" in finding.status_extended


@mock_aws
def test_vulnerable_bucket_combined_vulnerabilities(aws_credentials, check):
    """Test Case 1i: Bucket with disabled PAB, public policy, and public ACL reports all issues."""
    session = boto3.Session(region_name="us-east-1")
    s3 = session.client("s3", region_name="us-east-1")
    bucket_name = "test-fully-vulnerable-bucket"
    s3.create_bucket(Bucket=bucket_name)
    s3.put_bucket_policy(
        Bucket=bucket_name,
        Policy=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Sid": "PublicAccess",
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:*",
                "Resource": f"arn:aws:s3:::{bucket_name}/*",
            }],
        }),
    )
    s3.put_bucket_acl(Bucket=bucket_name, ACL="public-read-write")

    findings = check.run_check(session)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.status == Status.FAIL
    assert "Public Access Block incomplete" in finding.status_extended
    assert "Public Bucket Policy allows wildcard access" in finding.status_extended
    assert "Public ACL grants detected" in finding.status_extended


# ==============================================================================
# TEST CASE 2: Safe / Hardened Configurations (PASS)
# ==============================================================================

@mock_aws
def test_safe_bucket_fully_hardened(aws_credentials, check):
    """Test Case 2a: Bucket with all 4 public access blocks enabled and private ACL passes."""
    session = boto3.Session(region_name="us-east-1")
    s3 = session.client("s3", region_name="us-east-1")
    bucket_name = "test-secure-hardened-bucket"
    s3.create_bucket(Bucket=bucket_name)
    s3.put_public_access_block(
        Bucket=bucket_name,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )

    findings = check.run_check(session)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.status == Status.PASS
    assert finding.severity == Severity.CRITICAL
    assert finding.resource_id == bucket_name
    assert finding.resource_arn == f"arn:aws:s3:::{bucket_name}"
    assert "is secure: Public Access Block is fully enabled" in finding.status_extended
    assert "CIS-AWS-1.4" in finding.compliance
    assert "PCI-DSS-v3.2.1" in finding.compliance


@mock_aws
def test_safe_bucket_with_restrictive_policy_condition(aws_credentials, check):
    """Test Case 2b: Bucket with policy containing Principal '*' constrained by aws:PrincipalArn condition passes."""
    session = boto3.Session(region_name="us-east-1")
    s3 = session.client("s3", region_name="us-east-1")
    bucket_name = "test-restricted-policy-bucket"
    s3.create_bucket(Bucket=bucket_name)
    s3.put_public_access_block(
        Bucket=bucket_name,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )
    s3.put_bucket_policy(
        Bucket=bucket_name,
        Policy=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Sid": "RestrictedToSpecificRole",
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": f"arn:aws:s3:::{bucket_name}/*",
                "Condition": {
                    "StringEquals": {
                        "aws:PrincipalArn": "arn:aws:iam::123456789012:role/SecurityAuditor"
                    }
                },
            }],
        }),
    )

    findings = check.run_check(session)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.status == Status.PASS
    assert "is secure" in finding.status_extended


@mock_aws
def test_empty_account_no_buckets(aws_credentials, check):
    """Test Case 2c: AWS account with 0 S3 buckets returns empty findings list."""
    session = boto3.Session(region_name="us-east-1")
    findings = check.run_check(session)
    assert findings == []


# ==============================================================================
# TEST CASE 3: Access Denied / ClientError Handling (ACCESS_DENIED)
# ==============================================================================

def test_access_denied_on_list_buckets(check):
    """Test Case 3a: AccessDenied during list_buckets returns Status.ACCESS_DENIED."""
    client = boto3.client("s3", region_name="us-east-1")
    stubber = Stubber(client)
    stubber.add_client_error(
        "list_buckets",
        service_error_code="AccessDenied",
        service_message="User is not authorized to perform: s3:ListAllMyBuckets",
        http_status_code=403,
    )
    stubber.activate()

    mock_session = MagicMock()
    mock_session.client.return_value = client
    mock_session.region_name = "us-east-1"

    try:
        findings = check.run_check(mock_session)
        assert len(findings) == 1
        finding = findings[0]
        assert finding.status == Status.ACCESS_DENIED
        assert finding.resource_id == "arn:aws:s3:::*"
        assert "Access Denied listing S3 buckets: AccessDenied" in finding.status_extended
        assert "SecurityAudit" in finding.remediation.cli_command
    finally:
        stubber.deactivate()


def test_access_denied_on_get_bucket_location(check):
    """Test Case 3b: AccessDenied during get_bucket_location falls back to us-east-1 and continues audit."""
    client = boto3.client("s3", region_name="us-east-1")
    stubber = Stubber(client)
    stubber.add_response("list_buckets", {"Buckets": [{"Name": "loc-denied-bucket"}]})
    stubber.add_client_error(
        "get_bucket_location",
        service_error_code="AccessDenied",
        service_message="Forbidden to get bucket location",
        http_status_code=403,
    )
    stubber.add_response(
        "get_public_access_block",
        {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            }
        },
    )
    stubber.add_client_error(
        "get_bucket_policy",
        service_error_code="NoSuchBucketPolicy",
        service_message="The bucket policy does not exist",
    )
    stubber.add_response(
        "get_bucket_acl",
        {"Grants": []},
    )
    stubber.activate()

    mock_session = MagicMock()
    mock_session.client.return_value = client
    mock_session.region_name = "us-east-1"

    try:
        findings = check.run_check(mock_session)
        assert len(findings) == 1
        finding = findings[0]
        # Verified that location denial does NOT abort audit; bucket is audited and passes
        assert finding.status == Status.PASS
        assert finding.resource_id == "loc-denied-bucket"
        assert finding.region == "us-east-1"
    finally:
        stubber.deactivate()


def test_access_denied_on_get_public_access_block(check):
    """Test Case 3c: AccessDenied during get_public_access_block returns Status.ACCESS_DENIED."""
    client = boto3.client("s3", region_name="us-east-1")
    stubber = Stubber(client)
    stubber.add_response("list_buckets", {"Buckets": [{"Name": "pab-denied-bucket"}]})
    stubber.add_response("get_bucket_location", {"LocationConstraint": ""})
    stubber.add_client_error(
        "get_public_access_block",
        service_error_code="AccessDenied",
        service_message="Access Denied reading public access block",
        http_status_code=403,
    )
    stubber.activate()

    mock_session = MagicMock()
    mock_session.client.return_value = client
    mock_session.region_name = "us-east-1"

    try:
        findings = check.run_check(mock_session)
        assert len(findings) == 1
        finding = findings[0]
        assert finding.status == Status.ACCESS_DENIED
        assert finding.resource_id == "pab-denied-bucket"
        assert "Access Denied checking Public Access Block on bucket 'pab-denied-bucket'" in finding.status_extended
    finally:
        stubber.deactivate()


def test_access_denied_on_get_bucket_policy(check):
    """Test Case 3d: AccessDenied during get_bucket_policy returns Status.ACCESS_DENIED."""
    client = boto3.client("s3", region_name="us-east-1")
    stubber = Stubber(client)
    stubber.add_response("list_buckets", {"Buckets": [{"Name": "policy-denied-bucket"}]})
    stubber.add_response("get_bucket_location", {"LocationConstraint": ""})
    stubber.add_response(
        "get_public_access_block",
        {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            }
        },
    )
    stubber.add_client_error(
        "get_bucket_policy",
        service_error_code="AccessDenied",
        service_message="Access Denied reading bucket policy",
        http_status_code=403,
    )
    stubber.activate()

    mock_session = MagicMock()
    mock_session.client.return_value = client
    mock_session.region_name = "us-east-1"

    try:
        findings = check.run_check(mock_session)
        assert len(findings) == 1
        finding = findings[0]
        assert finding.status == Status.ACCESS_DENIED
        assert finding.resource_id == "policy-denied-bucket"
        assert "Access Denied checking policy on bucket 'policy-denied-bucket'" in finding.status_extended
    finally:
        stubber.deactivate()


def test_access_denied_on_get_bucket_acl(check):
    """Test Case 3e: AccessDenied during get_bucket_acl returns Status.ACCESS_DENIED."""
    client = boto3.client("s3", region_name="us-east-1")
    stubber = Stubber(client)
    stubber.add_response("list_buckets", {"Buckets": [{"Name": "acl-denied-bucket"}]})
    stubber.add_response("get_bucket_location", {"LocationConstraint": ""})
    stubber.add_response(
        "get_public_access_block",
        {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            }
        },
    )
    stubber.add_client_error(
        "get_bucket_policy",
        service_error_code="NoSuchBucketPolicy",
        service_message="The bucket policy does not exist",
    )
    stubber.add_client_error(
        "get_bucket_acl",
        service_error_code="AccessDenied",
        service_message="Access Denied reading bucket ACL",
        http_status_code=403,
    )
    stubber.activate()

    mock_session = MagicMock()
    mock_session.client.return_value = client
    mock_session.region_name = "us-east-1"

    try:
        findings = check.run_check(mock_session)
        assert len(findings) == 1
        finding = findings[0]
        assert finding.status == Status.ACCESS_DENIED
        assert finding.resource_id == "acl-denied-bucket"
        assert "Access Denied checking ACL on bucket 'acl-denied-bucket'" in finding.status_extended
    finally:
        stubber.deactivate()


def test_execute_wrapper_preserves_findings(check):
    """Test that check.execute(session) wrapper correctly preserves findings."""
    client = boto3.client("s3", region_name="us-east-1")
    stubber = Stubber(client)
    stubber.add_client_error(
        "list_buckets",
        service_error_code="UnauthorizedOperation",
        service_message="Not authorized",
        http_status_code=403,
    )
    stubber.activate()

    mock_session = MagicMock()
    mock_session.client.return_value = client
    mock_session.region_name = "us-east-1"

    try:
        findings = check.execute(mock_session)
        assert len(findings) == 1
        assert findings[0].status == Status.ACCESS_DENIED
    finally:
        stubber.deactivate()


def test_execute_wrapper_handles_unexpected_client_error(check):
    """Test that check.execute(session) wrapper transforms generic ClientError into Status.ERROR."""
    client = boto3.client("s3", region_name="us-east-1")
    stubber = Stubber(client)
    stubber.add_client_error(
        "list_buckets",
        service_error_code="InternalError",
        service_message="AWS internal failure",
        http_status_code=500,
    )
    stubber.activate()

    mock_session = MagicMock()
    mock_session.client.return_value = client
    mock_session.region_name = "us-east-1"

    try:
        findings = check.execute(mock_session)
        assert len(findings) == 1
        assert findings[0].status == Status.ERROR
        assert "InternalError" in findings[0].status_extended
    finally:
        stubber.deactivate()


def test_vulnerable_not_principal_bucket_policy(aws_credentials, check):
    """Test that bucket policy using Effect: Allow with NotPrincipal is flagged as FAIL."""
    with mock_aws():
        session = boto3.Session(region_name="us-east-1")
        s3 = session.client("s3", region_name="us-east-1")
        bucket_name = "vuln-not-principal-bucket"
        s3.create_bucket(Bucket=bucket_name)

        not_principal_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AllowAllExceptOne",
                    "Effect": "Allow",
                    "NotPrincipal": {"AWS": "arn:aws:iam::123456789012:user/excluded"},
                    "Action": "s3:GetObject",
                    "Resource": f"arn:aws:s3:::{bucket_name}/*",
                }
            ],
        }
        s3.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(not_principal_policy))

        findings = check.run_check(session)
        assert len(findings) == 1
        assert findings[0].status == Status.FAIL
        assert "NotPrincipal" in findings[0].status_extended


def test_wildcard_condition_value_does_not_pass(aws_credentials, check):
    """Test that condition block with wildcard value ('*') does not count as restrictive."""
    with mock_aws():
        session = boto3.Session(region_name="us-east-1")
        s3 = session.client("s3", region_name="us-east-1")
        bucket_name = "vuln-wildcard-condition-bucket"
        s3.create_bucket(Bucket=bucket_name)

        wildcard_cond_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "WildcardConditionAllow",
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "s3:GetObject",
                    "Resource": f"arn:aws:s3:::{bucket_name}/*",
                    "Condition": {
                        "StringEquals": {
                            "aws:PrincipalArn": "*"
                        }
                    },
                }
            ],
        }
        s3.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(wildcard_cond_policy))

        findings = check.run_check(session)
        assert len(findings) == 1
        assert findings[0].status == Status.FAIL
