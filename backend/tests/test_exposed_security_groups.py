"""
CloudSentinel Exposed Security Group Detection Engine Tests
Validates detection, reporting, remediation, and error handling for:
1. Vulnerable configurations (0.0.0.0/0 or ::/0 to SSH 22, RDP 3389, DB ports, all-traffic) -> Status.FAIL
2. Safe configurations (restricted CIDRs, web-only 80/443, empty ingress rules) -> Status.PASS
3. Permission failures (UnauthorizedOperation, AccessDenied) -> Status.ACCESS_DENIED
Matching and beating Prowler standards with comprehensive remediation guidance.
"""
from unittest.mock import MagicMock
import boto3
from botocore.exceptions import ClientError
from botocore.stub import Stubber
from moto import mock_aws
import pytest

from backend.scanner.checks.exposed_security_groups import ExposedSecurityGroupsCheck
from backend.scanner.models import Status, Severity
from backend.scanner.scoring import compute_scan_summary


@pytest.fixture
def check():
    """Return an instance of ExposedSecurityGroupsCheck."""
    return ExposedSecurityGroupsCheck()


@pytest.fixture
def aws_credentials(monkeypatch):
    """Mocked AWS credentials for moto."""
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")


# ==============================================================================
# TEST CASE 1: Vulnerable Configurations (FAIL) - Moto
# ==============================================================================

class TestExposedSecurityGroupsVulnerable:
    """Tests for vulnerable security group ingress configurations (FAIL)."""

    @mock_aws
    def test_vulnerable_sg_ssh_and_rdp_fails(self, aws_credentials, check):
        """
        Test Case 1: SG allowing 0.0.0.0/0 on port 22 and port 3389 must evaluate to Status.FAIL
        with Severity.CRITICAL and actionable remediation.
        """
        session = boto3.Session(region_name="us-east-1")
        ec2 = session.client("ec2", region_name="us-east-1")
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]

        sg_id = ec2.create_security_group(
            GroupName="launch-wizard-vulnerable",
            Description="Vulnerable admin group",
            VpcId=vpc,
        )["GroupId"]

        ec2.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                },
                {
                    "IpProtocol": "tcp",
                    "FromPort": 3389,
                    "ToPort": 3389,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                },
            ],
        )

        findings = check.execute(session, group_ids=[sg_id])

        assert len(findings) == 1
        finding = findings[0]
        assert finding.status == Status.FAIL
        assert finding.severity == Severity.CRITICAL
        assert finding.resource_id == sg_id
        assert "22" in finding.status_extended
        assert "3389" in finding.status_extended
        assert "aws ec2 revoke-security-group-ingress" in finding.remediation.cli_command
        assert "--port 22" in finding.remediation.cli_command
        assert "--port 3389" in finding.remediation.cli_command
        assert "aws_security_group_rule" in finding.remediation.terraform_fix
        assert "Session Manager" in finding.remediation.terraform_fix
        assert "CIS-AWS-1.4:5.2" in finding.compliance
        assert "CIS-AWS-1.4:5.3" in finding.compliance

    @mock_aws
    def test_vulnerable_sg_all_traffic_wildcard_fails(self, aws_credentials, check):
        """Ingress with IpProtocol == '-1' and 0.0.0.0/0 must fail with CRITICAL severity."""
        session = boto3.Session(region_name="us-east-1")
        ec2 = session.client("ec2", region_name="us-east-1")
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]

        sg_id = ec2.create_security_group(
            GroupName="all-traffic-wildcard",
            Description="Open to everything",
            VpcId=vpc,
        )["GroupId"]

        ec2.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[
                {
                    "IpProtocol": "-1",
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                }
            ],
        )

        findings = check.execute(session, group_ids=[sg_id])

        assert len(findings) == 1
        finding = findings[0]
        assert finding.status == Status.FAIL
        assert finding.severity == Severity.CRITICAL
        assert "ALL traffic/ports" in finding.status_extended
        assert "--protocol all" in finding.remediation.cli_command

    @mock_aws
    def test_vulnerable_sg_database_ports_fails(self, aws_credentials, check):
        """
        Ingress from 0.0.0.0/0 to database ports (3306 MySQL, 5432 Postgres, 1433 MSSQL, 27017 Mongo)
        must fail with HIGH severity.
        """
        session = boto3.Session(region_name="us-east-1")
        ec2 = session.client("ec2", region_name="us-east-1")
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]

        db_ports = [
            (3306, "MySQL"),
            (5432, "PostgreSQL"),
            (1433, "MSSQL"),
            (27017, "MongoDB"),
        ]

        for port, db_name in db_ports:
            sg_id = ec2.create_security_group(
                GroupName=f"db-{port}-open",
                Description=f"Open {db_name}",
                VpcId=vpc,
            )["GroupId"]

            ec2.authorize_security_group_ingress(
                GroupId=sg_id,
                IpPermissions=[
                    {
                        "IpProtocol": "tcp",
                        "FromPort": port,
                        "ToPort": port,
                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                    }
                ],
            )

            findings = check.execute(session, group_ids=[sg_id])
            assert len(findings) == 1
            finding = findings[0]
            assert finding.status == Status.FAIL
            assert finding.severity == Severity.HIGH
            assert str(port) in finding.status_extended
            assert finding.check_id == "ec2_securitygroup_allow_ingress_db_ports"

    @mock_aws
    def test_vulnerable_sg_ipv6_ssh_fails(self, aws_credentials, check):
        """Ingress from IPv6 '::/0' to port 22 must fail with CRITICAL severity."""
        session = boto3.Session(region_name="us-east-1")
        ec2 = session.client("ec2", region_name="us-east-1")
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]

        sg_id = ec2.create_security_group(
            GroupName="ipv6-open-ssh",
            Description="Open IPv6 SSH",
            VpcId=vpc,
        )["GroupId"]

        ec2.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
                }
            ],
        )

        findings = check.execute(session, group_ids=[sg_id])
        assert len(findings) == 1
        finding = findings[0]
        assert finding.status == Status.FAIL
        assert finding.severity == Severity.CRITICAL
        assert "::/0" in finding.status_extended
        assert finding.check_id == "ec2_securitygroup_allow_ingress_port_22"

    @mock_aws
    def test_vulnerable_sg_port_range_covering_sensitive_port(self, aws_credentials, check):
        """
        Port range from 20 to 25 open to 0.0.0.0/0 covers SSH (port 22).
        Must evaluate to Status.FAIL and remediation CLI must generate exact boundary '--port 20-25'
        to prevent AWS EC2 InvalidPermission.NotFound.
        """
        session = boto3.Session(region_name="us-east-1")
        ec2 = session.client("ec2", region_name="us-east-1")
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]

        sg_id = ec2.create_security_group(
            GroupName="range-covering-ssh",
            Description="Covers 22",
            VpcId=vpc,
        )["GroupId"]

        ec2.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[
                {
                    "IpProtocol": "tcp",
                    "FromPort": 20,
                    "ToPort": 25,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                }
            ],
        )

        findings = check.execute(session, group_ids=[sg_id])
        assert len(findings) == 1
        finding = findings[0]
        assert finding.status == Status.FAIL
        assert finding.severity == Severity.CRITICAL
        assert "SSH" in finding.status_extended
        assert "20-25" in finding.status_extended

        # Exact rule boundary must be used in remediation CLI to avoid InvalidPermission.NotFound
        assert "--port 20-25" in finding.remediation.cli_command
        assert "--port 22" not in finding.remediation.cli_command
        assert f"aws ec2 revoke-security-group-ingress --group-id {sg_id} --protocol tcp --port 20-25 --cidr 0.0.0.0/0" in finding.remediation.cli_command

        # Confirm that revoking with the generated range succeeds in EC2 without error
        ec2.revoke_security_group_ingress(
            GroupId=sg_id,
            IpProtocol="tcp",
            FromPort=20,
            ToPort=25,
            CidrIp="0.0.0.0/0",
        )

    @mock_aws
    def test_vulnerable_sg_ipv6_port_range_remediation(self, aws_credentials, check):
        """IPv6 ingress with port range 3000 to 3500 covering RDP (3389) generates correct FromPort/ToPort."""
        session = boto3.Session(region_name="us-east-1")
        ec2 = session.client("ec2", region_name="us-east-1")
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]

        sg_id = ec2.create_security_group(
            GroupName="ipv6-range-covering-rdp",
            Description="Covers 3389",
            VpcId=vpc,
        )["GroupId"]

        ec2.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[
                {
                    "IpProtocol": "tcp",
                    "FromPort": 3000,
                    "ToPort": 3500,
                    "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
                }
            ],
        )

        findings = check.execute(session, group_ids=[sg_id])
        assert len(findings) == 1
        finding = findings[0]
        assert finding.status == Status.FAIL
        assert "FromPort\": 3000" in finding.remediation.cli_command
        assert "ToPort\": 3500" in finding.remediation.cli_command


# ==============================================================================
# TEST CASE 2: Safe Configurations (PASS) - Moto
# ==============================================================================

class TestExposedSecurityGroupsSafe:
    """Tests for hardened / compliant security group ingress configurations (PASS)."""

    @mock_aws
    def test_safe_sg_private_cidr_passes(self, aws_credentials, check):
        """
        Test Case 2a: SG with private CIDRs (10.0.0.0/8, 192.168.1.0/24, or single /32)
        on sensitive ports must evaluate to Status.PASS.
        """
        session = boto3.Session(region_name="us-east-1")
        ec2 = session.client("ec2", region_name="us-east-1")
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]

        sg_id = ec2.create_security_group(
            GroupName="internal-bastion-sg",
            Description="Private corporate bastion",
            VpcId=vpc,
        )["GroupId"]

        ec2.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [
                        {"CidrIp": "10.0.0.0/8"},
                        {"CidrIp": "192.168.1.0/24"},
                        {"CidrIp": "198.51.100.14/32"},
                    ],
                },
                {
                    "IpProtocol": "tcp",
                    "FromPort": 3389,
                    "ToPort": 3389,
                    "IpRanges": [{"CidrIp": "172.16.0.0/12"}],
                },
            ],
        )

        findings = check.execute(session, group_ids=[sg_id])

        assert len(findings) == 1
        finding = findings[0]
        assert finding.status == Status.PASS
        assert finding.severity == Severity.LOW
        assert finding.resource_id == sg_id
        assert "compliant ingress rules" in finding.status_extended
        assert finding.check_id == "ec2_securitygroup_safe_ingress"

    @mock_aws
    def test_safe_sg_web_ports_only_passes(self, aws_credentials, check):
        """
        Test Case 2b: SG restricted to standard public web traffic (80/443)
        without sensitive management ports must evaluate to Status.PASS.
        """
        session = boto3.Session(region_name="us-east-1")
        ec2 = session.client("ec2", region_name="us-east-1")
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]

        sg_id = ec2.create_security_group(
            GroupName="public-alb-web-sg",
            Description="Public ALB web tier",
            VpcId=vpc,
        )["GroupId"]

        ec2.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[
                {
                    "IpProtocol": "tcp",
                    "FromPort": 80,
                    "ToPort": 80,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                    "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
                },
                {
                    "IpProtocol": "tcp",
                    "FromPort": 443,
                    "ToPort": 443,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                    "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
                },
            ],
        )

        findings = check.execute(session, group_ids=[sg_id])

        assert len(findings) == 1
        finding = findings[0]
        assert finding.status == Status.PASS
        assert finding.severity == Severity.LOW
        assert finding.resource_id == sg_id

    @mock_aws
    def test_safe_sg_no_ingress_rules_passes(self, aws_credentials, check):
        """
        Test Case 2c: Security group with no ingress rules (default hardened posture)
        must evaluate to Status.PASS.
        """
        session = boto3.Session(region_name="us-east-1")
        ec2 = session.client("ec2", region_name="us-east-1")
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]

        sg_id = ec2.create_security_group(
            GroupName="isolated-database-sg",
            Description="No ingress rules",
            VpcId=vpc,
        )["GroupId"]

        findings = check.execute(session, group_ids=[sg_id])

        assert len(findings) == 1
        finding = findings[0]
        assert finding.status == Status.PASS
        assert finding.severity == Severity.LOW


# ==============================================================================
# TEST CASE 3: Access-Denied & Error Handling - Stubber / Mocking
# ==============================================================================

class TestExposedSecurityGroupsAccessDenied:
    """Tests for IAM permission failure handling (ACCESS_DENIED)."""

    def test_access_denied_unauthorized_operation(self, check):
        """
        Test Case 3: ClientError with UnauthorizedOperation on describe_security_groups
        must return Status.ACCESS_DENIED finding without crashing.
        """
        session = boto3.Session(region_name="us-east-1")
        ec2 = session.client("ec2", region_name="us-east-1")
        stubber = Stubber(ec2)

        stubber.add_client_error(
            "describe_security_groups",
            service_error_code="UnauthorizedOperation",
            service_message="You are not authorized to perform this operation.",
        )
        stubber.activate()

        mock_session = MagicMock()
        mock_session.client.return_value = ec2
        mock_session.region_name = "us-east-1"

        findings = check.execute(mock_session)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.status == Status.ACCESS_DENIED
        assert finding.service == "ec2"
        assert "UnauthorizedOperation" in finding.status_extended
        assert "SecurityAudit" in finding.remediation.cli_command
        assert "aws_iam_role_policy_attachment" in finding.remediation.terraform_fix

    def test_access_denied_exception_code(self, check):
        """ClientError with AccessDenied code must return Status.ACCESS_DENIED."""
        session = boto3.Session(region_name="us-east-1")
        ec2 = session.client("ec2", region_name="us-east-1")
        stubber = Stubber(ec2)

        stubber.add_client_error(
            "describe_security_groups",
            service_error_code="AccessDenied",
            service_message="User is not authorized to describe security groups.",
        )
        stubber.activate()

        mock_session = MagicMock()
        mock_session.client.return_value = ec2
        mock_session.region_name = "us-east-1"

        findings = check.execute(mock_session)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.status == Status.ACCESS_DENIED
        assert "AccessDenied" in finding.status_extended

    def test_run_check_directly_returns_access_denied(self, check):
        """Calling run_check directly when UnauthorizedOperation occurs returns ACCESS_DENIED."""
        session = boto3.Session(region_name="us-east-1")
        ec2 = session.client("ec2", region_name="us-east-1")
        stubber = Stubber(ec2)

        stubber.add_client_error(
            "describe_security_groups",
            service_error_code="UnauthorizedOperation",
            service_message="Access denied directly in run_check.",
        )
        stubber.activate()

        mock_session = MagicMock()
        mock_session.client.return_value = ec2
        mock_session.region_name = "us-east-1"

        findings = check.run_check(mock_session)
        assert len(findings) == 1
        assert findings[0].status == Status.ACCESS_DENIED


# ==============================================================================
# TEST CASE 4: Stubber Payload Verification
# ==============================================================================

class TestExposedSecurityGroupsStubber:
    """Precise API stubbing tests verifying exact parsing of Security Group dictionaries."""

    def test_stubbed_vulnerable_sg(self, check):
        """Stubber test for SG with open SSH and RDP."""
        session = boto3.Session(region_name="us-east-1")
        ec2 = session.client("ec2", region_name="us-east-1")
        stubber = Stubber(ec2)

        response = {
            "SecurityGroups": [
                {
                    "GroupId": "sg-01a2b3c4d5e6f7g8h",
                    "GroupName": "launch-wizard-1",
                    "Description": "Test launch wizard",
                    "OwnerId": "123456789012",
                    "IpPermissions": [
                        {
                            "IpProtocol": "tcp",
                            "FromPort": 22,
                            "ToPort": 22,
                            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                            "Ipv6Ranges": [],
                            "PrefixListIds": [],
                            "UserIdGroupPairs": [],
                        },
                        {
                            "IpProtocol": "tcp",
                            "FromPort": 3389,
                            "ToPort": 3389,
                            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                            "Ipv6Ranges": [],
                            "PrefixListIds": [],
                            "UserIdGroupPairs": [],
                        },
                    ],
                    "IpPermissionsEgress": [],
                    "VpcId": "vpc-0123456789abcdef0",
                }
            ]
        }

        stubber.add_response("describe_security_groups", response, {})
        stubber.activate()

        mock_session = MagicMock()
        mock_session.client.return_value = ec2
        mock_session.region_name = "us-east-1"

        findings = check.execute(mock_session)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.status == Status.FAIL
        assert finding.severity == Severity.CRITICAL
        assert finding.resource_id == "sg-01a2b3c4d5e6f7g8h"
        assert "22" in finding.status_extended
        assert "3389" in finding.status_extended

    def test_stubbed_safe_sg(self, check):
        """Stubber test for SG with private IP only."""
        session = boto3.Session(region_name="us-east-1")
        ec2 = session.client("ec2", region_name="us-east-1")
        stubber = Stubber(ec2)

        response = {
            "SecurityGroups": [
                {
                    "GroupId": "sg-safe-corp",
                    "GroupName": "corporate-sg",
                    "Description": "Corporate private only",
                    "OwnerId": "123456789012",
                    "IpPermissions": [
                        {
                            "IpProtocol": "tcp",
                            "FromPort": 22,
                            "ToPort": 22,
                            "IpRanges": [{"CidrIp": "10.100.0.0/16"}],
                            "Ipv6Ranges": [],
                            "PrefixListIds": [],
                            "UserIdGroupPairs": [],
                        }
                    ],
                    "IpPermissionsEgress": [],
                    "VpcId": "vpc-0123456789abcdef0",
                }
            ]
        }

        stubber.add_response("describe_security_groups", response, {})
        stubber.activate()

        mock_session = MagicMock()
        mock_session.client.return_value = ec2
        mock_session.region_name = "us-east-1"

        findings = check.execute(mock_session)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.status == Status.PASS
        assert finding.resource_id == "sg-safe-corp"


# ==============================================================================
# TEST CASE 5: Scoring Integration & Completeness
# ==============================================================================

class TestScoringIntegration:
    """Verifies that findings from ExposedSecurityGroupsCheck integrate with the scoring engine."""

    @mock_aws
    def test_scan_summary_computation(self, aws_credentials, check):
        """Verify weighted scoring correctly accounts for exposed security group findings."""
        session = boto3.Session(region_name="us-east-1")
        ec2 = session.client("ec2", region_name="us-east-1")
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]

        # 1 Vulnerable SG (Port 22 open) -> CRITICAL FAIL
        vuln_sg = ec2.create_security_group(GroupName="vuln-sg", Description="vuln", VpcId=vpc)["GroupId"]
        ec2.authorize_security_group_ingress(
            GroupId=vuln_sg,
            IpPermissions=[{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
        )

        # 1 Safe SG (Only 443 open) -> PASS
        safe_sg = ec2.create_security_group(GroupName="safe-sg", Description="safe", VpcId=vpc)["GroupId"]
        ec2.authorize_security_group_ingress(
            GroupId=safe_sg,
            IpPermissions=[{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
        )

        findings = check.execute(session, group_ids=[vuln_sg, safe_sg])
        summary, explanation = compute_scan_summary(findings)

        assert summary.total_checks == 2
        assert summary.failed_checks == 1
        assert summary.passed_checks == 1
        assert summary.access_denied_checks == 0
        assert summary.is_complete is True
        assert summary.security_score < 100.0
        assert summary.severity_breakdown[Severity.CRITICAL.value] == 1
