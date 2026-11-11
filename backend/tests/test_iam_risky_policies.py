"""
CloudSentinel Unit Tests: IAM Risky Policies Detection Engine
Covers:
1. Vulnerable configurations (FAIL):
   - Admin wildcard policies (Effect=Allow, Action=*, Resource=*)
   - Privilege escalation vectors (iam:PassRole + ec2:RunInstances, iam:CreatePolicyVersion, etc.)
2. Safe / hardened configurations (PASS):
   - Read-only policies (s3:GetObject, ec2:Describe*)
   - Scoped least-privilege policies
   - Empty customer policies baseline
3. AccessDenied / ClientError handling (ACCESS_DENIED):
   - ListPolicies AccessDenied
   - GetPolicyVersion AccessDenied
   - UnauthorizedOperation handling
4. ThreatScore calculation integration
5. Remediation completeness (CLI, Terraform snippet, Documentation URL)
"""
import json
import os
import sys
import pytest
import boto3
import botocore.exceptions
from botocore.stub import Stubber
from unittest.mock import MagicMock
import moto

# Ensure backend directory is in python search path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from scanner.models import Status, Severity
from scanner.checks.iam_risky_policies import IAMRiskyPoliciesCheck
from scanner.scoring import compute_scan_summary


@pytest.fixture
def iam_check():
    return IAMRiskyPoliciesCheck()


@pytest.fixture
def aws_credentials(monkeypatch):
    """Set mock AWS credentials for testing with moto."""
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")


# =============================================================================
# TEST CASE 1: Vulnerable Configurations (FAIL)
# =============================================================================

class TestVulnerableIAMPolicies:
    """Verifies detection of administrative wildcards and privilege escalation vectors."""

    def test_vulnerable_admin_wildcard_policy(self, aws_credentials, iam_check):
        """
        Test Case 1A: Policy with Action='*' and Resource='*' without conditions.
        Must evaluate to status == FAIL and severity == CRITICAL.
        """
        with moto.mock_aws():
            session = boto3.Session(region_name="us-east-1")
            iam = session.client("iam")

            policy_doc = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "*",
                        "Resource": "*",
                    }
                ],
            }

            resp = iam.create_policy(
                PolicyName="CustomAdminWildcardPolicy",
                PolicyDocument=json.dumps(policy_doc),
            )
            policy_arn = resp["Policy"]["Arn"]

            findings = iam_check.run_check(session)

            assert len(findings) == 1
            f = findings[0]
            assert f.status == Status.FAIL
            assert f.severity == Severity.CRITICAL
            assert f.check_id == "iam_policy_wildcard_administrative_access"
            assert f.resource_id == "CustomAdminWildcardPolicy"
            assert f.resource_arn == policy_arn
            assert "full administrative wildcard" in f.status_extended.lower()

            # Verify comprehensive remediation fields
            assert f.remediation.description
            assert f.remediation.recommendation
            assert "aws iam delete-policy" in f.remediation.cli_command
            assert "data \"aws_iam_policy_document\"" in f.remediation.terraform_fix
            assert f.remediation.documentation_url

    def test_vulnerable_passrole_ec2_runinstances(self, aws_credentials, iam_check):
        """
        Test Case 1B: Policy with iam:PassRole combined with ec2:RunInstances.
        Must evaluate to status == FAIL and severity == CRITICAL.
        """
        with moto.mock_aws():
            session = boto3.Session(region_name="us-east-1")
            iam = session.client("iam")

            policy_doc = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "iam:PassRole",
                            "ec2:RunInstances",
                        ],
                        "Resource": "*",
                    }
                ],
            }

            resp = iam.create_policy(
                PolicyName="PassRoleEC2EscalationPolicy",
                PolicyDocument=json.dumps(policy_doc),
            )
            policy_arn = resp["Policy"]["Arn"]

            findings = iam_check.run_check(session)

            assert len(findings) == 1
            f = findings[0]
            assert f.status == Status.FAIL
            assert f.severity == Severity.CRITICAL
            assert f.check_id == "iam_policy_allows_privilege_escalation"
            assert f.resource_id == "PassRoleEC2EscalationPolicy"
            assert f.resource_arn == policy_arn
            assert "iam:passrole_ec2" in f.status_extended.lower()

            # Verify remediation
            assert "iam:PassedToService" in f.remediation.terraform_fix
            assert "aws iam create-policy-version" in f.remediation.cli_command
            assert f.remediation.documentation_url

    def test_vulnerable_combined_admin_and_privesc_policies(self, aws_credentials, iam_check):
        """
        Test Case 1C: Both vulnerable policies in account (wildcard and PassRole+ec2).
        Verifies both are detected and flagged as FAIL.
        """
        with moto.mock_aws():
            session = boto3.Session(region_name="us-east-1")
            iam = session.client("iam")

            admin_doc = {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
            }
            privesc_doc = {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": ["iam:PassRole", "ec2:RunInstances"], "Resource": "*"}
                ],
            }

            iam.create_policy(PolicyName="AdminPolicy", PolicyDocument=json.dumps(admin_doc))
            iam.create_policy(PolicyName="PrivEscPolicy", PolicyDocument=json.dumps(privesc_doc))

            findings = iam_check.execute(session)

            assert len(findings) == 2
            for f in findings:
                assert f.status == Status.FAIL
                assert f.severity == Severity.CRITICAL

            check_ids = {f.check_id for f in findings}
            assert "iam_policy_wildcard_administrative_access" in check_ids
            assert "iam_policy_allows_privilege_escalation" in check_ids

    @pytest.mark.parametrize(
        "vector_name,actions",
        [
            ("iam:CreatePolicyVersion", ["iam:CreatePolicyVersion"]),
            ("iam:SetDefaultPolicyVersion", ["iam:SetDefaultPolicyVersion"]),
            ("iam:PassRole_Lambda", ["iam:PassRole", "lambda:CreateFunction"]),
            ("iam:AttachUserPolicy", ["iam:AttachUserPolicy"]),
            ("iam:AttachGroupPolicy", ["iam:AttachGroupPolicy"]),
            ("iam:AttachRolePolicy", ["iam:AttachRolePolicy"]),
            ("iam:PutUserPolicy", ["iam:PutUserPolicy"]),
            ("iam:PutGroupPolicy", ["iam:PutGroupPolicy"]),
            ("iam:PutRolePolicy", ["iam:PutRolePolicy"]),
            ("iam:UpdateAssumeRolePolicy", ["iam:UpdateAssumeRolePolicy"]),
            ("iam:CreateAccessKey", ["iam:CreateAccessKey"]),
            ("iam:CreateLoginProfile", ["iam:CreateLoginProfile"]),
            ("iam:UpdateLoginProfile", ["iam:UpdateLoginProfile"]),
            ("iam:AddUserToGroup", ["iam:AddUserToGroup"]),
        ],
    )
    def test_all_known_privilege_escalation_vectors(self, iam_check, vector_name, actions):
        """
        Parameterized test verifying every recognized AWS privilege escalation permission.
        """
        doc = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": actions,
                    "Resource": "*",
                }
            ],
        }

        finding = iam_check.evaluate_policy(
            policy_name=f"Policy_{vector_name.replace(':', '_')}",
            policy_arn=f"arn:aws:iam::123456789012:policy/Policy_{vector_name}",
            document=doc,
        )

        assert finding.status == Status.FAIL
        assert finding.severity == Severity.CRITICAL
        assert finding.check_id == "iam_policy_allows_privilege_escalation"
        assert len(finding.remediation.cli_command) > 0
        assert len(finding.remediation.terraform_fix) > 0


# =============================================================================
# TEST CASE 2: Safe / Hardened Configurations (PASS)
# =============================================================================

class TestSafeIAMPolicies:
    """Verifies that compliant, read-only, and least-privilege policies evaluate to PASS."""

    def test_safe_policy_read_only_actions(self, aws_credentials, iam_check):
        """
        Test Case 2A: Policy with read-only actions (s3:GetObject, ec2:Describe*).
        Must evaluate to status == PASS.
        """
        with moto.mock_aws():
            session = boto3.Session(region_name="us-east-1")
            iam = session.client("iam")

            policy_doc = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "s3:GetObject",
                            "ec2:DescribeInstances",
                            "ec2:DescribeSecurityGroups",
                            "ec2:DescribeSubnets",
                        ],
                        "Resource": "*",
                    }
                ],
            }

            resp = iam.create_policy(
                PolicyName="AppReadOnlyPolicy",
                PolicyDocument=json.dumps(policy_doc),
            )
            policy_arn = resp["Policy"]["Arn"]

            findings = iam_check.run_check(session)

            assert len(findings) == 1
            f = findings[0]
            assert f.status == Status.PASS
            assert f.check_id == "iam_policy_least_privilege"
            assert f.resource_id == "AppReadOnlyPolicy"
            assert f.resource_arn == policy_arn
            assert "least-privilege" in f.status_extended.lower()
            assert "compliant" in f.remediation.cli_command.lower()

    def test_safe_policy_scoped_resources(self, iam_check):
        """
        Test Case 2B: Policy scoped to specific S3 bucket and CloudWatch logs.
        Must evaluate to status == PASS.
        """
        doc = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["s3:GetObject", "s3:PutObject"],
                    "Resource": "arn:aws:s3:::my-secure-bucket/*",
                },
                {
                    "Effect": "Allow",
                    "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
                    "Resource": "arn:aws:logs:us-east-1:123456789012:log-group:/aws/lambda/*",
                },
            ],
        }

        finding = iam_check.evaluate_policy(
            policy_name="ScopedApplicationPolicy",
            policy_arn="arn:aws:iam::123456789012:policy/ScopedApplicationPolicy",
            document=doc,
        )

        assert finding.status == Status.PASS
        assert finding.check_id == "iam_policy_least_privilege"

    def test_safe_passrole_scoped_with_passed_to_service_condition(self, iam_check):
        """
        Policy with iam:PassRole scoped to a specific non-wildcard role ARN
        with an iam:PassedToService condition key adheres to least privilege
        and must evaluate to status == PASS.
        """
        doc = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["iam:PassRole"],
                    "Resource": "arn:aws:iam::123456789012:role/SpecificAppExecutionRole",
                    "Condition": {
                        "StringEquals": {
                            "iam:PassedToService": "ec2.amazonaws.com"
                        }
                    },
                },
                {
                    "Effect": "Allow",
                    "Action": ["ec2:RunInstances"],
                    "Resource": "*",
                },
            ],
        }

        finding = iam_check.evaluate_policy(
            policy_name="HardenedScopedPassRolePolicy",
            policy_arn="arn:aws:iam::123456789012:policy/HardenedScopedPassRolePolicy",
            document=doc,
        )

        assert finding.status == Status.PASS
        assert finding.check_id == "iam_policy_least_privilege"
        assert "least-privilege" in finding.status_extended.lower()

    def test_safe_passrole_in_moto_scan(self, aws_credentials, iam_check):
        """
        End-to-end moto scan verifying that a customer managed policy with
        scoped iam:PassRole and iam:PassedToService condition returns PASS.
        """
        with moto.mock_aws():
            session = boto3.Session(region_name="us-east-1")
            iam = session.client("iam")

            hardened_doc = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["iam:PassRole"],
                        "Resource": "arn:aws:iam::123456789012:role/SpecificAppExecutionRole",
                        "Condition": {
                            "StringEquals": {
                                "iam:PassedToService": "ec2.amazonaws.com"
                            }
                        },
                    },
                    {
                        "Effect": "Allow",
                        "Action": ["ec2:RunInstances"],
                        "Resource": "*",
                    },
                ],
            }

            resp = iam.create_policy(
                PolicyName="HardenedPassRolePolicy",
                PolicyDocument=json.dumps(hardened_doc),
            )

            findings = iam_check.run_check(session)
            assert len(findings) == 1
            f = findings[0]
            assert f.status == Status.PASS
            assert f.check_id == "iam_policy_least_privilege"
            assert f.resource_arn == resp["Policy"]["Arn"]

    def test_safe_empty_account_customer_policies(self, aws_credentials, iam_check):
        """
        Test Case 2C: Account with zero customer managed policies.
        Must return empty list cleanly without error, matching S3, EC2, EBS, and RDS behavior.
        """
        with moto.mock_aws():
            session = boto3.Session(region_name="us-east-1")
            findings = iam_check.run_check(session)

            assert findings == []

    def test_deny_statements_are_not_flagged_as_vulnerable(self, iam_check):
        """
        Statements with Effect: Deny should never be flagged as admin wildcard or privesc.
        """
        doc = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Deny",
                    "Action": "*",
                    "Resource": "*",
                }
            ],
        }

        finding = iam_check.evaluate_policy(
            policy_name="GlobalDenyAllPolicy",
            policy_arn="arn:aws:iam::123456789012:policy/GlobalDenyAllPolicy",
            document=doc,
        )

        assert finding.status == Status.PASS


# =============================================================================
# TEST CASE 3: AccessDenied / ClientError Handling (ACCESS_DENIED)
# =============================================================================

class TestAccessDeniedIAMPolicies:
    """Verifies that AccessDenied / ClientError permissions issues return ACCESS_DENIED."""

    def test_access_denied_on_list_policies(self, iam_check):
        """
        Test Case 3A: iam.list_policies raises ClientError with AccessDenied.
        Must catch exception and return finding with status == ACCESS_DENIED.
        """
        mock_session = MagicMock()
        mock_iam = MagicMock()
        mock_session.client.return_value = mock_iam

        error_response = {
            "Error": {
                "Code": "AccessDenied",
                "Message": "User is not authorized to perform: iam:ListPolicies on resource: *",
            }
        }
        mock_iam.get_paginator.side_effect = botocore.exceptions.ClientError(
            error_response, "ListPolicies"
        )

        findings = iam_check.run_check(mock_session)

        assert len(findings) == 1
        f = findings[0]
        assert f.status == Status.ACCESS_DENIED
        assert f.check_id == "iam_risky_policies"
        assert "AccessDenied" in f.status_extended
        assert "SecurityAudit" in f.remediation.recommendation
        assert "SecurityAudit" in f.remediation.cli_command
        assert "SecurityAudit" in f.remediation.terraform_fix

    def test_access_denied_on_get_policy_version(self, iam_check):
        """
        Test Case 3B: list_policies succeeds, but get_policy_version raises AccessDenied.
        Must return finding with status == ACCESS_DENIED for that policy.
        """
        mock_session = MagicMock()
        mock_iam = MagicMock()
        mock_session.client.return_value = mock_iam

        # Return 1 policy from paginator
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [
            {
                "Policies": [
                    {
                        "PolicyName": "RestrictedPolicy",
                        "Arn": "arn:aws:iam::123456789012:policy/RestrictedPolicy",
                        "DefaultVersionId": "v1",
                    }
                ]
            }
        ]
        mock_iam.get_paginator.return_value = mock_paginator

        # get_policy_version raises AccessDenied
        error_response = {
            "Error": {
                "Code": "AccessDeniedException",
                "Message": "Explicit deny on iam:GetPolicyVersion",
            }
        }
        mock_iam.get_policy_version.side_effect = botocore.exceptions.ClientError(
            error_response, "GetPolicyVersion"
        )

        findings = iam_check.run_check(mock_session)

        assert len(findings) == 1
        f = findings[0]
        assert f.status == Status.ACCESS_DENIED
        assert f.resource_id == "RestrictedPolicy"
        assert "AccessDeniedException" in f.status_extended

    def test_unauthorized_operation_error(self, iam_check):
        """
        Test Case 3C: ClientError with UnauthorizedOperation code.
        Must evaluate to status == ACCESS_DENIED.
        """
        mock_session = MagicMock()
        mock_iam = MagicMock()
        mock_session.client.return_value = mock_iam

        error_response = {
            "Error": {
                "Code": "UnauthorizedOperation",
                "Message": "You are not authorized to perform this operation.",
            }
        }
        mock_iam.get_paginator.side_effect = botocore.exceptions.ClientError(
            error_response, "ListPolicies"
        )

        findings = iam_check.execute(mock_session)

        assert len(findings) == 1
        f = findings[0]
        assert f.status == Status.ACCESS_DENIED


# =============================================================================
# ADDITIONAL TESTS: Document Parsing & ThreatScore Integration
# =============================================================================

class TestDocumentParsingAndThreatScore:
    """Verifies edge cases in policy document parsing and scoring calculations."""

    def test_url_encoded_policy_document_handling(self, iam_check):
        """Documents delivered as URL-encoded JSON strings are decoded cleanly."""
        raw_doc = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "*", "Resource": "*"}
            ],
        }
        url_encoded_doc = "%7B%22Version%22%3A%20%222012-10-17%22%2C%20%22Statement%22%3A%20%5B%7B%22Effect%22%3A%20%22Allow%22%2C%20%22Action%22%3A%20%22%2A%22%2C%20%22Resource%22%3A%20%22%2A%22%7D%5D%7D"

        finding = iam_check.evaluate_policy(
            policy_name="URLEncodedAdmin",
            policy_arn="arn:aws:iam::123456789012:policy/URLEncodedAdmin",
            document=url_encoded_doc,
        )

        assert finding.status == Status.FAIL
        assert finding.check_id == "iam_policy_wildcard_administrative_access"

    def test_single_statement_as_dict(self, iam_check):
        """Statements defined as a single dict rather than a list parse accurately."""
        doc = {
            "Version": "2012-10-17",
            "Statement": {
                "Effect": "Allow",
                "Action": "iam:CreateAccessKey",
                "Resource": "*",
            },
        }

        finding = iam_check.evaluate_policy(
            policy_name="SingleDictPrivesc",
            policy_arn="arn:aws:iam::123456789012:policy/SingleDictPrivesc",
            document=doc,
        )

        assert finding.status == Status.FAIL
        assert finding.check_id == "iam_policy_allows_privilege_escalation"

    def test_not_action_wildcard_resource_is_flagged(self, iam_check):
        """Statement using NotAction with wildcard resource is flagged as admin wildcard."""
        doc = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "NotAction": "iam:*",
                    "Resource": "*",
                }
            ],
        }

        finding = iam_check.evaluate_policy(
            policy_name="NotActionAdminBypass",
            policy_arn="arn:aws:iam::123456789012:policy/NotActionAdminBypass",
            document=doc,
        )

        assert finding.status == Status.FAIL
        assert finding.check_id == "iam_policy_wildcard_administrative_access"

    def test_admin_wildcard_with_restrictive_condition(self, iam_check):
        """Wildcard policy bounded by restrictive condition is not flagged as unrestricted admin."""
        doc = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "*",
                    "Resource": "*",
                    "Condition": {
                        "Bool": {"aws:MultiFactorAuthPresent": "true"}
                    },
                }
            ],
        }

        finding = iam_check.evaluate_policy(
            policy_name="MFARestrictedAdmin",
            policy_arn="arn:aws:iam::123456789012:policy/MFARestrictedAdmin",
            document=doc,
        )

        # Because it has a restrictive MFA condition, it does not flag as unrestricted admin wildcard (*:*)
        assert finding.check_id != "iam_policy_wildcard_administrative_access"

    def test_admin_wildcard_with_non_restrictive_condition_flags(self, iam_check):
        """Wildcard policy with trivial non-security condition must still flag as admin wildcard (Finding 8)."""
        doc = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "*",
                    "Resource": "*",
                    "Condition": {
                        "StringEquals": {"s3:prefix": "home/"}
                    },
                }
            ],
        }

        finding = iam_check.evaluate_policy(
            policy_name="DummyConditionAdmin",
            policy_arn="arn:aws:iam::123456789012:policy/DummyConditionAdmin",
            document=doc,
        )

        assert finding.status == Status.FAIL
        assert finding.check_id == "iam_policy_wildcard_administrative_access"

    def test_invalid_document_strings(self, iam_check):
        """Malformed document strings parse to empty dictionary without raising exceptions."""
        finding = iam_check.evaluate_policy(
            policy_name="InvalidJSONPolicy",
            policy_arn="arn:aws:iam::123456789012:policy/InvalidJSONPolicy",
            document="not-valid-json{[[",
        )
        assert finding.status == Status.PASS

    def test_list_policies_fallback_when_not_pageable(self, iam_check):
        """Falls back to direct list_policies call when paginator raises OperationNotPageableError."""
        mock_session = MagicMock()
        mock_iam = MagicMock()
        mock_session.client.return_value = mock_iam
        mock_iam.get_paginator.side_effect = botocore.exceptions.OperationNotPageableError(
            operation_name="list_policies"
        )
        mock_iam.list_policies.return_value = {
            "Policies": [
                {
                    "Arn": "arn:aws:iam::123456789012:policy/CustomReadOnly",
                    "PolicyName": "CustomReadOnly",
                    "DefaultVersionId": "v1",
                }
            ]
        }
        mock_iam.get_policy_version.return_value = {
            "PolicyVersion": {
                "Document": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": "s3:GetObject",
                            "Resource": "*",
                        }
                    ],
                }
            }
        }

        findings = iam_check.run_check(mock_session)
        assert len(findings) == 1
        assert findings[0].status == Status.PASS

    def test_unexpected_client_error_on_get_policy_version_raises(self, iam_check):
        """Unexpected ClientError other than AccessDenied is re-raised."""
        mock_session = MagicMock()
        mock_iam = MagicMock()
        mock_session.client.return_value = mock_iam

        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [
            {"Policies": [{"PolicyName": "P", "Arn": "arn:aws:iam::1:policy/P", "DefaultVersionId": "v1"}]}
        ]
        mock_iam.get_paginator.return_value = mock_paginator

        error_response = {"Error": {"Code": "InternalError", "Message": "IAM backend failure"}}
        mock_iam.get_policy_version.side_effect = botocore.exceptions.ClientError(
            error_response, "GetPolicyVersion"
        )

        with pytest.raises(botocore.exceptions.ClientError):
            iam_check.run_check(mock_session)

    def test_document_with_no_statements(self, iam_check):
        """Documents without Statement key evaluate safely as PASS."""
        doc = {"Version": "2012-10-17"}
        finding = iam_check.evaluate_policy("EmptyDoc", "arn:aws:iam::1:policy/Empty", doc)
        assert finding.status == Status.PASS

    def test_scoring_summary_with_mixed_iam_findings(self, iam_check):
        """
        Verifies that findings integrate correctly into the scoring engine:
        - Passed findings add weight
        - Failed findings reduce score
        - AccessDenied findings are excluded from pass points and mark scan incomplete
        """
        # Create 1 PASS finding, 1 FAIL finding, 1 ACCESS_DENIED finding
        safe_doc = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}],
        }
        vulnerable_doc = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
        }

        pass_f = iam_check.evaluate_policy("SafePolicy", "arn:aws:iam::1:policy/Safe", safe_doc)
        fail_f = iam_check.evaluate_policy("FailPolicy", "arn:aws:iam::1:policy/Fail", vulnerable_doc)
        denied_f = iam_check._build_access_denied_finding("arn:aws:iam::1:policy/Denied", "AccessDenied", "Forbidden")

        summary, explanation = compute_scan_summary([pass_f, fail_f, denied_f])

        assert summary.total_checks == 3
        assert summary.passed_checks == 1
        assert summary.failed_checks == 1
        assert summary.access_denied_checks == 1
        assert summary.is_complete is False
        assert summary.security_score == 50.0  # 10 pass / (10 pass + 10 fail) = 50%
        assert "AccessDenied" in explanation["incomplete_notice"]
