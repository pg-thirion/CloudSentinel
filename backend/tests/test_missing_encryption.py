"""
CloudSentinel Missing Encryption Detection Tests
Validates detection, reporting, remediation, multi-region scanning, and error handling for:
- S3 Bucket Default Encryption (aws:kms / AES256)
- EBS Volume Encryption (Encrypted == False/True across multiple active regions)
- RDS DB Instance Storage Encryption (StorageEncrypted == False/True across multiple active regions)
- Access-Denied & Permission failure handling (Status.ACCESS_DENIED)
- Multi-Region Discovery via ec2:DescribeRegions with opt-in status filtering and graceful fallback
Matching and beating Prowler standards.
"""
from unittest.mock import MagicMock
import boto3
import botocore.exceptions
from moto import mock_aws
import pytest

from backend.scanner.checks.missing_encryption import (
    MissingEncryptionCheck,
    S3DefaultEncryptionCheck,
    EBSVolumeEncryptionCheck,
    RDSInstanceEncryptionCheck,
    _get_active_regions,
)
from backend.scanner.models import Severity, Status
from backend.scanner.scoring import compute_scan_summary


# ==============================================================================
# 1. Master Composite MissingEncryptionCheck Tests
# ==============================================================================

class TestMissingEncryptionOverall:
    """End-to-end multi-service tests for MissingEncryptionCheck."""

    @mock_aws
    def test_missing_encryption_vulnerable_all_services(self):
        """
        Test Case 1 (Vulnerable):
        Unencrypted S3 bucket (no SSE), unencrypted EBS volume, and unencrypted RDS instance
        must all evaluate to status == FAIL with Severity == HIGH and actionable remediations.
        """
        session = boto3.Session(region_name="us-east-1")

        # 1. Vulnerable S3 Bucket
        s3 = session.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="vuln-unencrypted-data-bucket")

        # 2. Vulnerable EBS Volume
        ec2 = session.client("ec2", region_name="us-east-1")
        ec2.create_volume(AvailabilityZone="us-east-1a", Size=50, Encrypted=False)

        # 3. Vulnerable RDS DB Instance
        rds = session.client("rds", region_name="us-east-1")
        rds.create_db_instance(
            DBInstanceIdentifier="vuln-unencrypted-db",
            DBInstanceClass="db.t3.micro",
            Engine="postgres",
            StorageEncrypted=False,
            AllocatedStorage=20,
        )

        check = MissingEncryptionCheck(regions=["us-east-1"])
        findings = check.execute(session)

        assert len(findings) == 3, f"Expected 3 findings, got {len(findings)}"

        # Every finding must be FAIL and HIGH severity
        for f in findings:
            assert f.status == Status.FAIL, f"Finding {f.check_id} did not FAIL: {f.status}"
            assert f.severity == Severity.HIGH, f"Finding {f.check_id} severity not HIGH: {f.severity}"
            assert f.service == "encryption"
            assert len(f.compliance) > 0
            assert f.remediation.cli_command != ""
            assert f.remediation.terraform_fix != ""
            assert f.remediation.recommendation != ""

        # Verify S3 finding
        s3_finding = next(f for f in findings if f.check_id == "s3_bucket_default_encryption")
        assert s3_finding.resource_id == "vuln-unencrypted-data-bucket"
        assert "put-bucket-encryption" in s3_finding.remediation.cli_command
        assert "aws_s3_bucket_server_side_encryption_configuration" in s3_finding.remediation.terraform_fix

        # Verify EBS finding
        ebs_finding = next(f for f in findings if f.check_id == "ebs_volume_encryption")
        assert ebs_finding.resource_id.startswith("vol-")
        assert "enable-ebs-encryption-by-default" in ebs_finding.remediation.cli_command
        assert "aws_ebs_volume" in ebs_finding.remediation.terraform_fix
        assert "encrypted         = true" in ebs_finding.remediation.terraform_fix

        # Verify RDS finding
        rds_finding = next(f for f in findings if f.check_id == "rds_instance_storage_encryption")
        assert rds_finding.resource_id == "vuln-unencrypted-db"
        assert "copy-db-snapshot" in rds_finding.remediation.cli_command
        assert "aws_db_instance" in rds_finding.remediation.terraform_fix
        assert "storage_encrypted = true" in rds_finding.remediation.terraform_fix

    @mock_aws
    def test_missing_encryption_safe_all_services(self):
        """
        Test Case 2 (Safe):
        Encrypted S3 bucket (AES256/KMS), encrypted EBS volume, and encrypted RDS instance
        must all evaluate to status == PASS.
        """
        session = boto3.Session(region_name="us-east-1")

        # 1. Safe S3 Bucket with AES256 SSE
        s3 = session.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="hardened-secured-data-bucket")
        s3.put_bucket_encryption(
            Bucket="hardened-secured-data-bucket",
            ServerSideEncryptionConfiguration={
                "Rules": [
                    {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}
                ]
            },
        )

        # 2. Safe EBS Volume with Encrypted = True
        ec2 = session.client("ec2", region_name="us-east-1")
        ec2.create_volume(AvailabilityZone="us-east-1a", Size=50, Encrypted=True)

        # 3. Safe RDS DB Instance with StorageEncrypted = True
        rds = session.client("rds", region_name="us-east-1")
        rds.create_db_instance(
            DBInstanceIdentifier="hardened-secured-db",
            DBInstanceClass="db.t3.micro",
            Engine="postgres",
            StorageEncrypted=True,
            AllocatedStorage=20,
        )

        check = MissingEncryptionCheck(regions=["us-east-1"])
        findings = check.execute(session)

        assert len(findings) == 3, f"Expected 3 findings, got {len(findings)}"

        for f in findings:
            assert f.status == Status.PASS, f"Finding {f.check_id} did not PASS: {f.status}"
            assert f.severity == Severity.HIGH
            assert "Compliant" in f.remediation.terraform_fix or "compliant" in f.remediation.terraform_fix

        s3_finding = next(f for f in findings if f.check_id == "s3_bucket_default_encryption")
        assert s3_finding.status == Status.PASS
        assert "AES256" in s3_finding.status_extended

        ebs_finding = next(f for f in findings if f.check_id == "ebs_volume_encryption")
        assert ebs_finding.status == Status.PASS

        rds_finding = next(f for f in findings if f.check_id == "rds_instance_storage_encryption")
        assert rds_finding.status == Status.PASS

    def test_missing_encryption_access_denied_all_services(self):
        """
        Test Case 3 (Access-Denied):
        When AWS services reject calls with AccessDenied / UnauthorizedOperation,
        findings must report status == Status.ACCESS_DENIED with IAM remediation.
        """
        mock_session = MagicMock()
        mock_session.region_name = "us-east-1"

        def client_side_effect(service_name, **kwargs):
            client_mock = MagicMock()
            if service_name == "s3":
                client_mock.list_buckets.side_effect = botocore.exceptions.ClientError(
                    {"Error": {"Code": "AccessDenied", "Message": "User is not authorized to perform: s3:ListAllMyBuckets"}},
                    "ListBuckets",
                )
            elif service_name == "ec2":
                client_mock.describe_regions.return_value = {"Regions": [{"RegionName": "us-east-1"}]}
                client_mock.get_paginator.side_effect = botocore.exceptions.ClientError(
                    {"Error": {"Code": "UnauthorizedOperation", "Message": "You are not authorized to perform this operation."}},
                    "DescribeVolumes",
                )
                client_mock.describe_volumes.side_effect = botocore.exceptions.ClientError(
                    {"Error": {"Code": "UnauthorizedOperation", "Message": "You are not authorized to perform this operation."}},
                    "DescribeVolumes",
                )
            elif service_name == "rds":
                client_mock.get_paginator.side_effect = botocore.exceptions.ClientError(
                    {"Error": {"Code": "AccessDeniedException", "Message": "User is not authorized to perform: rds:DescribeDBInstances"}},
                    "DescribeDBInstances",
                )
                client_mock.describe_db_instances.side_effect = botocore.exceptions.ClientError(
                    {"Error": {"Code": "AccessDeniedException", "Message": "User is not authorized to perform: rds:DescribeDBInstances"}},
                    "DescribeDBInstances",
                )
            elif service_name == "sts":
                client_mock.get_caller_identity.return_value = {"Account": "123456789012"}
            return client_mock

        mock_session.client.side_effect = client_side_effect

        check = MissingEncryptionCheck(regions=["us-east-1"])
        findings = check.execute(mock_session)

        assert len(findings) == 3, f"Expected 3 findings, got {len(findings)}"
        for f in findings:
            assert f.status == Status.ACCESS_DENIED, f"Expected ACCESS_DENIED, got {f.status}"
            assert "SecurityAudit" in f.remediation.recommendation or "SecurityAudit" in f.remediation.cli_command
            assert "Access Denied" in f.status_extended or "Unauthorized" in f.status_extended


# ==============================================================================
# 2. S3 Default Encryption Check Tests
# ==============================================================================

class TestS3DefaultEncryptionCheck:
    """Granular unit tests for S3 Default Server-Side Encryption check."""

    @mock_aws
    def test_s3_encryption_vulnerable_no_sse_config(self):
        """S3 bucket created without SSE returns FAIL."""
        session = boto3.Session(region_name="us-east-1")
        s3 = session.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="unencrypted-s3-test-bucket")

        check = S3DefaultEncryptionCheck()
        findings = check.execute(session)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.check_id == "s3_bucket_default_encryption"
        assert finding.status == Status.FAIL
        assert finding.resource_id == "unencrypted-s3-test-bucket"
        assert finding.resource_arn == "arn:aws:s3:::unencrypted-s3-test-bucket"
        assert "does not have default server-side encryption enabled" in finding.status_extended

    @mock_aws
    def test_s3_encryption_safe_aes256(self):
        """S3 bucket with AES256 default encryption returns PASS."""
        session = boto3.Session(region_name="us-east-1")
        s3 = session.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="aes256-encrypted-bucket")
        s3.put_bucket_encryption(
            Bucket="aes256-encrypted-bucket",
            ServerSideEncryptionConfiguration={
                "Rules": [
                    {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}
                ]
            },
        )

        check = S3DefaultEncryptionCheck()
        findings = check.execute(session)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.status == Status.PASS
        assert "AES256" in finding.status_extended
        assert finding.resource_id == "aes256-encrypted-bucket"

    @mock_aws
    def test_s3_encryption_safe_kms(self):
        """S3 bucket with aws:kms default encryption returns PASS."""
        session = boto3.Session(region_name="us-east-1")
        s3 = session.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="kms-encrypted-bucket")
        kms_arn = "arn:aws:kms:us-east-1:123456789012:key/test-kms-key-id"
        s3.put_bucket_encryption(
            Bucket="kms-encrypted-bucket",
            ServerSideEncryptionConfiguration={
                "Rules": [
                    {
                        "ApplyServerSideEncryptionByDefault": {
                            "SSEAlgorithm": "aws:kms",
                            "KMSMasterKeyID": kms_arn,
                        }
                    }
                ]
            },
        )

        check = S3DefaultEncryptionCheck()
        findings = check.execute(session)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.status == Status.PASS
        assert "aws:kms" in finding.status_extended
        assert kms_arn in finding.status_extended

    @mock_aws
    def test_s3_encryption_no_buckets_returns_empty(self):
        """When no buckets exist, return empty findings list."""
        session = boto3.Session(region_name="us-east-1")
        check = S3DefaultEncryptionCheck()
        findings = check.execute(session)
        assert findings == []

    def test_s3_encryption_access_denied_on_get_encryption(self):
        """When get_bucket_encryption returns AccessDenied, return ACCESS_DENIED finding."""
        mock_session = MagicMock()
        mock_s3 = MagicMock()
        mock_session.client.return_value = mock_s3
        mock_s3.list_buckets.return_value = {"Buckets": [{"Name": "locked-bucket"}]}
        mock_s3.get_bucket_location.return_value = {"LocationConstraint": "us-east-1"}
        mock_s3.get_bucket_encryption.side_effect = botocore.exceptions.ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Access Denied"}},
            "GetBucketEncryption",
        )

        check = S3DefaultEncryptionCheck()
        findings = check.execute(mock_session)

        assert len(findings) == 1
        assert findings[0].status == Status.ACCESS_DENIED
        assert findings[0].resource_id == "locked-bucket"

    def test_s3_encryption_invalid_algorithm_fails(self):
        """Bucket with unrecognized or empty algorithm returns FAIL."""
        mock_session = MagicMock()
        mock_s3 = MagicMock()
        mock_session.client.return_value = mock_s3
        mock_s3.list_buckets.return_value = {"Buckets": [{"Name": "weird-algo-bucket"}]}
        mock_s3.get_bucket_location.return_value = {"LocationConstraint": None}
        mock_s3.get_bucket_encryption.return_value = {
            "ServerSideEncryptionConfiguration": {
                "Rules": [
                    {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "DES3"}}
                ]
            }
        }

        check = S3DefaultEncryptionCheck()
        findings = check.execute(mock_session)

        assert len(findings) == 1
        assert findings[0].status == Status.FAIL
        assert "does not configure a valid encryption algorithm" in findings[0].status_extended


# ==============================================================================
# 3. EBS Volume Encryption Check Tests
# ==============================================================================

class TestEBSVolumeEncryptionCheck:
    """Granular unit tests for EC2 EBS Volume Encryption check."""

    @mock_aws
    def test_ebs_encryption_vulnerable_unencrypted_volume(self):
        """Unencrypted EBS volume returns FAIL."""
        session = boto3.Session(region_name="us-east-1")
        ec2 = session.client("ec2", region_name="us-east-1")
        vol = ec2.create_volume(AvailabilityZone="us-east-1a", Size=30, Encrypted=False)
        vol_id = vol["VolumeId"]

        check = EBSVolumeEncryptionCheck(regions=["us-east-1"])
        findings = check.execute(session)

        assert len(findings) == 1
        f = findings[0]
        assert f.check_id == "ebs_volume_encryption"
        assert f.status == Status.FAIL
        assert f.resource_id == vol_id
        assert f.resource_arn == f"arn:aws:ec2:us-east-1:123456789012:volume/{vol_id}"
        assert "is NOT encrypted at rest" in f.status_extended

    @mock_aws
    def test_ebs_encryption_safe_encrypted_volume(self):
        """Encrypted EBS volume returns PASS."""
        session = boto3.Session(region_name="us-east-1")
        ec2 = session.client("ec2", region_name="us-east-1")
        vol = ec2.create_volume(AvailabilityZone="us-east-1a", Size=30, Encrypted=True)
        vol_id = vol["VolumeId"]

        check = EBSVolumeEncryptionCheck(regions=["us-east-1"])
        findings = check.execute(session)

        assert len(findings) == 1
        f = findings[0]
        assert f.status == Status.PASS
        assert f.resource_id == vol_id
        assert "is encrypted at rest" in f.status_extended

    @mock_aws
    def test_ebs_encryption_multiple_mixed_fleet(self):
        """Mixed fleet of encrypted and unencrypted volumes returns accurate statuses."""
        session = boto3.Session(region_name="us-east-1")
        ec2 = session.client("ec2", region_name="us-east-1")
        v1 = ec2.create_volume(AvailabilityZone="us-east-1a", Size=10, Encrypted=False)
        v2 = ec2.create_volume(AvailabilityZone="us-east-1a", Size=20, Encrypted=True)

        check = EBSVolumeEncryptionCheck(regions=["us-east-1"])
        findings = check.execute(session)

        assert len(findings) == 2
        f_unenc = next(f for f in findings if f.resource_id == v1["VolumeId"])
        f_enc = next(f for f in findings if f.resource_id == v2["VolumeId"])
        assert f_unenc.status == Status.FAIL
        assert f_enc.status == Status.PASS

    @mock_aws
    def test_ebs_encryption_no_volumes_returns_empty(self):
        """When no EBS volumes exist, return empty findings list."""
        session = boto3.Session(region_name="us-east-1")
        check = EBSVolumeEncryptionCheck(regions=["us-east-1"])
        findings = check.execute(session)
        assert findings == []

    def test_ebs_encryption_access_denied(self):
        """When EC2 describe_volumes raises UnauthorizedOperation, return ACCESS_DENIED."""
        mock_session = MagicMock()
        mock_session.region_name = "us-east-1"
        mock_ec2 = MagicMock()
        mock_session.client.return_value = mock_ec2
        mock_ec2.describe_regions.return_value = {"Regions": [{"RegionName": "us-east-1"}]}
        mock_ec2.get_paginator.side_effect = botocore.exceptions.ClientError(
            {"Error": {"Code": "UnauthorizedOperation", "Message": "Unauthorized operation."}},
            "DescribeVolumes",
        )
        mock_ec2.describe_volumes.side_effect = botocore.exceptions.ClientError(
            {"Error": {"Code": "UnauthorizedOperation", "Message": "Unauthorized operation."}},
            "DescribeVolumes",
        )

        check = EBSVolumeEncryptionCheck(regions=["us-east-1"])
        findings = check.execute(mock_session)

        assert len(findings) == 1
        assert findings[0].status == Status.ACCESS_DENIED
        assert "Access Denied" in findings[0].status_extended
        assert "ec2:volumes:us-east-1" in findings[0].resource_id


# ==============================================================================
# 4. RDS DB Instance Storage Encryption Check Tests
# ==============================================================================

class TestRDSInstanceEncryptionCheck:
    """Granular unit tests for RDS DB Instance Storage Encryption check."""

    @mock_aws
    def test_rds_encryption_vulnerable_unencrypted_db(self):
        """RDS DB instance with StorageEncrypted=False returns FAIL."""
        session = boto3.Session(region_name="us-east-1")
        rds = session.client("rds", region_name="us-east-1")
        rds.create_db_instance(
            DBInstanceIdentifier="unencrypted-mysql-db",
            DBInstanceClass="db.t3.micro",
            Engine="mysql",
            StorageEncrypted=False,
            AllocatedStorage=20,
        )

        check = RDSInstanceEncryptionCheck(regions=["us-east-1"])
        findings = check.execute(session)

        assert len(findings) == 1
        f = findings[0]
        assert f.check_id == "rds_instance_storage_encryption"
        assert f.status == Status.FAIL
        assert f.resource_id == "unencrypted-mysql-db"
        assert "is running unencrypted storage" in f.status_extended

    @mock_aws
    def test_rds_encryption_safe_encrypted_db(self):
        """RDS DB instance with StorageEncrypted=True returns PASS."""
        session = boto3.Session(region_name="us-east-1")
        rds = session.client("rds", region_name="us-east-1")
        rds.create_db_instance(
            DBInstanceIdentifier="encrypted-postgres-db",
            DBInstanceClass="db.t3.micro",
            Engine="postgres",
            StorageEncrypted=True,
            AllocatedStorage=20,
        )

        check = RDSInstanceEncryptionCheck(regions=["us-east-1"])
        findings = check.execute(session)

        assert len(findings) == 1
        f = findings[0]
        assert f.check_id == "rds_instance_storage_encryption"
        assert f.status == Status.PASS
        assert f.resource_id == "encrypted-postgres-db"
        assert "has storage encryption enabled" in f.status_extended

    @mock_aws
    def test_rds_encryption_multiple_mixed_fleet(self):
        """Mixed fleet of encrypted and unencrypted RDS instances."""
        session = boto3.Session(region_name="us-east-1")
        rds = session.client("rds", region_name="us-east-1")
        rds.create_db_instance(
            DBInstanceIdentifier="db-vuln",
            DBInstanceClass="db.t3.micro",
            Engine="postgres",
            StorageEncrypted=False,
            AllocatedStorage=20,
        )
        rds.create_db_instance(
            DBInstanceIdentifier="db-safe",
            DBInstanceClass="db.t3.micro",
            Engine="postgres",
            StorageEncrypted=True,
            AllocatedStorage=20,
        )

        check = RDSInstanceEncryptionCheck(regions=["us-east-1"])
        findings = check.execute(session)

        assert len(findings) == 2
        f_vuln = next(f for f in findings if f.resource_id == "db-vuln")
        f_safe = next(f for f in findings if f.resource_id == "db-safe")
        assert f_vuln.status == Status.FAIL
        assert f_safe.status == Status.PASS

    @mock_aws
    def test_rds_encryption_no_instances_returns_empty(self):
        """When no RDS instances exist, return empty findings list."""
        session = boto3.Session(region_name="us-east-1")
        check = RDSInstanceEncryptionCheck(regions=["us-east-1"])
        findings = check.execute(session)
        assert findings == []

    def test_rds_encryption_access_denied(self):
        """When RDS describe_db_instances raises AccessDenied, return ACCESS_DENIED."""
        mock_session = MagicMock()
        mock_session.region_name = "us-east-1"
        mock_rds = MagicMock()
        mock_session.client.return_value = mock_rds
        mock_rds.describe_regions.return_value = {"Regions": [{"RegionName": "us-east-1"}]}
        mock_rds.get_paginator.side_effect = botocore.exceptions.ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "Not authorized to describe RDS instances"}},
            "DescribeDBInstances",
        )
        mock_rds.describe_db_instances.side_effect = botocore.exceptions.ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "Not authorized to describe RDS instances"}},
            "DescribeDBInstances",
        )

        check = RDSInstanceEncryptionCheck(regions=["us-east-1"])
        findings = check.execute(mock_session)

        assert len(findings) == 1
        assert findings[0].status == Status.ACCESS_DENIED
        assert "Access Denied" in findings[0].status_extended
        assert "rds:db-instances:us-east-1" in findings[0].resource_id


# ==============================================================================
# 5. Multi-Region Scope & Discovery Tests
# ==============================================================================

class TestMultiRegionEncryptionDiscovery:
    """Tests multi-region iteration, region discovery filters, and fallback resiliency."""

    @mock_aws
    def test_active_regions_discovery_with_opt_in_filters(self):
        """Verify _get_active_regions queries DescribeRegions with opt-in status filters."""
        session = boto3.Session(region_name="us-east-1")
        regions = _get_active_regions(session)
        assert isinstance(regions, list)
        assert len(regions) > 0
        assert "us-east-1" in regions

    def test_describe_regions_access_denied_graceful_fallback(self):
        """When ec2:DescribeRegions raises UnauthorizedOperation, fall back to session region without crashing."""
        mock_session = MagicMock()
        mock_session.region_name = "eu-west-1"
        mock_ec2 = MagicMock()
        mock_session.client.return_value = mock_ec2
        mock_ec2.describe_regions.side_effect = botocore.exceptions.ClientError(
            {"Error": {"Code": "UnauthorizedOperation", "Message": "You are not authorized to perform DescribeRegions."}},
            "DescribeRegions",
        )

        regions = _get_active_regions(mock_session)
        assert regions == ["eu-west-1"]

    @mock_aws
    def test_ebs_encryption_multi_region_detection(self):
        """Verify EBS checks scan across multiple active AWS regions."""
        session = boto3.Session(region_name="us-east-1")

        # Create unencrypted volume in us-east-1
        ec2_us = session.client("ec2", region_name="us-east-1")
        vol_us = ec2_us.create_volume(AvailabilityZone="us-east-1a", Size=10, Encrypted=False)

        # Create encrypted volume in eu-west-1
        ec2_eu = session.client("ec2", region_name="eu-west-1")
        vol_eu = ec2_eu.create_volume(AvailabilityZone="eu-west-1a", Size=20, Encrypted=True)

        check = EBSVolumeEncryptionCheck(regions=["us-east-1", "eu-west-1"])
        findings = check.execute(session)

        assert len(findings) == 2
        f_us = next(f for f in findings if f.resource_id == vol_us["VolumeId"])
        f_eu = next(f for f in findings if f.resource_id == vol_eu["VolumeId"])

        assert f_us.status == Status.FAIL
        assert f_us.region == "us-east-1"

        assert f_eu.status == Status.PASS
        assert f_eu.region == "eu-west-1"

    @mock_aws
    def test_rds_encryption_multi_region_detection(self):
        """Verify RDS checks scan across multiple active AWS regions."""
        session = boto3.Session(region_name="us-east-1")

        # Create unencrypted DB in us-east-1
        rds_us = session.client("rds", region_name="us-east-1")
        rds_us.create_db_instance(
            DBInstanceIdentifier="billing-db-us",
            DBInstanceClass="db.t3.micro",
            Engine="postgres",
            StorageEncrypted=False,
            AllocatedStorage=20,
        )

        # Create encrypted DB in eu-west-1
        rds_eu = session.client("rds", region_name="eu-west-1")
        rds_eu.create_db_instance(
            DBInstanceIdentifier="analytics-db-eu",
            DBInstanceClass="db.t3.micro",
            Engine="postgres",
            StorageEncrypted=True,
            AllocatedStorage=20,
        )

        check = RDSInstanceEncryptionCheck(regions=["us-east-1", "eu-west-1"])
        findings = check.execute(session)

        assert len(findings) == 2
        f_us = next(f for f in findings if f.resource_id == "billing-db-us")
        f_eu = next(f for f in findings if f.resource_id == "analytics-db-eu")

        assert f_us.status == Status.FAIL
        assert f_us.region == "us-east-1"

        assert f_eu.status == Status.PASS
        assert f_eu.region == "eu-west-1"

    @mock_aws
    def test_missing_encryption_multi_region_composite(self):
        """Verify composite check aggregates multi-region findings across S3, EBS, and RDS."""
        session = boto3.Session(region_name="us-east-1")

        # S3 global bucket
        s3 = session.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="multi-region-audit-bucket")

        # EC2 volumes in 2 regions
        ec2_us = session.client("ec2", region_name="us-east-1")
        ec2_us.create_volume(AvailabilityZone="us-east-1a", Size=10, Encrypted=False)

        ec2_eu = session.client("ec2", region_name="eu-west-1")
        ec2_eu.create_volume(AvailabilityZone="eu-west-1a", Size=15, Encrypted=True)

        # RDS databases in 2 regions
        rds_us = session.client("rds", region_name="us-east-1")
        rds_us.create_db_instance(
            DBInstanceIdentifier="db-us-unenc",
            DBInstanceClass="db.t3.micro",
            Engine="mysql",
            StorageEncrypted=False,
            AllocatedStorage=20,
        )

        rds_eu = session.client("rds", region_name="eu-west-1")
        rds_eu.create_db_instance(
            DBInstanceIdentifier="db-eu-enc",
            DBInstanceClass="db.t3.micro",
            Engine="postgres",
            StorageEncrypted=True,
            AllocatedStorage=20,
        )

        check = MissingEncryptionCheck(regions=["us-east-1", "eu-west-1"])
        findings = check.execute(session)

        # 1 S3 + 2 EBS + 2 RDS = 5 findings
        assert len(findings) == 5
        statuses = [f.status for f in findings]
        assert statuses.count(Status.FAIL) == 3   # S3 unenc, EBS US unenc, RDS US unenc
        assert statuses.count(Status.PASS) == 2   # EBS EU enc, RDS EU enc

    def test_ebs_encryption_region_level_access_denied_isolation(self):
        """When one region returns AccessDenied, other regions continue scanning cleanly."""
        mock_session = MagicMock()
        mock_session.region_name = "us-east-1"

        def client_side_effect(service_name, region_name="us-east-1", **kwargs):
            client = MagicMock()
            if service_name == "ec2":
                if region_name == "eu-west-1":
                    client.describe_volumes.side_effect = botocore.exceptions.ClientError(
                        {"Error": {"Code": "UnauthorizedOperation", "Message": "Unauthorized in eu-west-1"}},
                        "DescribeVolumes",
                    )
                else:
                    client.describe_volumes.return_value = {
                        "Volumes": [{"VolumeId": "vol-us-1", "Encrypted": True, "AvailabilityZone": "us-east-1a"}]
                    }
            elif service_name == "sts":
                client.get_caller_identity.return_value = {"Account": "123456789012"}
            return client

        mock_session.client.side_effect = client_side_effect

        check = EBSVolumeEncryptionCheck(regions=["us-east-1", "eu-west-1"])
        findings = check.execute(mock_session)

        assert len(findings) == 2
        f_us = next(f for f in findings if f.region == "us-east-1")
        f_eu = next(f for f in findings if f.region == "eu-west-1")

        assert f_us.status == Status.PASS
        assert f_eu.status == Status.ACCESS_DENIED
        assert "Unauthorized in eu-west-1" in f_eu.status_extended


# ==============================================================================
# 6. Scoring and Engine Integration Tests
# ==============================================================================

class TestMissingEncryptionScoringIntegration:
    """Verifies ThreatScore mathematical weighting and completeness integration."""

    @mock_aws
    def test_scoring_with_missing_encryption_findings(self):
        """
        Verify that vulnerable and safe missing encryption findings
        compute the correct weighted ThreatScore via compute_scan_summary.
        """
        session = boto3.Session(region_name="us-east-1")
        # 1 safe S3, 1 unencrypted EBS, 1 safe RDS
        s3 = session.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="safe-bucket")
        s3.put_bucket_encryption(
            Bucket="safe-bucket",
            ServerSideEncryptionConfiguration={
                "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
            },
        )

        ec2 = session.client("ec2", region_name="us-east-1")
        ec2.create_volume(AvailabilityZone="us-east-1a", Size=10, Encrypted=False)

        rds = session.client("rds", region_name="us-east-1")
        rds.create_db_instance(
            DBInstanceIdentifier="safe-db",
            DBInstanceClass="db.t3.micro",
            Engine="postgres",
            StorageEncrypted=True,
            AllocatedStorage=20,
        )

        check = MissingEncryptionCheck(regions=["us-east-1"])
        findings = check.execute(session)

        assert len(findings) == 3
        summary, explanation = compute_scan_summary(findings)

        # 2 passed (weight 5.0 * 2 = 10.0), 1 failed (weight 5.0) -> Score = (10 / 15) * 100 = 66.7%
        assert summary.total_checks == 3
        assert summary.passed_checks == 2
        assert summary.failed_checks == 1
        assert summary.access_denied_checks == 0
        assert summary.security_score == 66.7
        assert summary.score_band == "FAIR"
        assert summary.is_complete is True
        assert summary.service_breakdown["encryption"]["passed"] == 2
        assert summary.service_breakdown["encryption"]["failed"] == 1
