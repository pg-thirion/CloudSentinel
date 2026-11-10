"""
CloudSentinel Realistic Mock Findings
Provides calibrated demonstration findings mirroring Prowler scan results
across all 4 categories for demo and testing without live AWS credentials.
"""
from typing import List, Dict, Any
from .models import Finding, Severity, Status, Remediation
from .scoring import compute_scan_summary


def get_mock_findings() -> List[Finding]:
    """Returns curated findings representing vulnerable, safe, and access-denied cases."""
    return [
        # --- CATEGORY 1: S3 Public Access ---
        Finding(
            check_id="s3_bucket_public_access",
            check_title="Ensure Amazon S3 Buckets Prohibit Public Access",
            service="s3",
            severity=Severity.CRITICAL,
            status=Status.FAIL,
            status_extended="Bucket 'prod-financial-reports-2026' has BlockPublicAccess disabled and contains a public policy allowing s3:GetObject to wildcard principal.",
            resource_id="prod-financial-reports-2026",
            resource_arn="arn:aws:s3:::prod-financial-reports-2026",
            region="us-east-1",
            remediation=Remediation(
                description="Public S3 buckets expose company confidential data directly to the internet.",
                recommendation="Enable S3 Public Access Block at bucket or account level, and restrict bucket policy to specific VPC or IAM roles.",
                cli_command="aws s3api put-public-access-block \\\n  --bucket prod-financial-reports-2026 \\\n  --public-access-block-configuration \"BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true\"",
                terraform_fix="resource \"aws_s3_bucket_public_access_block\" \"financial_reports\" {\n  bucket = \"prod-financial-reports-2026\"\n\n  block_public_acls       = true\n  block_public_policy     = true\n  ignore_public_acls      = true\n  restrict_public_buckets = true\n}",
                documentation_url="https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
            ),
            compliance=["CIS-AWS-1.4:2.1.5", "NIST-800-53:AC-3", "PCI-DSS-4.0:7.2"],
        ),
        Finding(
            check_id="s3_bucket_public_access",
            check_title="Ensure Amazon S3 Buckets Prohibit Public Access",
            service="s3",
            severity=Severity.CRITICAL,
            status=Status.PASS,
            status_extended="Bucket 'internal-app-audit-logs' has all 4 BlockPublicAccess flags enabled and no public ACLs/policies.",
            resource_id="internal-app-audit-logs",
            resource_arn="arn:aws:s3:::internal-app-audit-logs",
            region="us-east-1",
            remediation=Remediation(
                description="Bucket is private and properly hardened.",
                recommendation="Maintain current configuration.",
                cli_command="# Bucket is safe. Verification command:\naws s3api get-public-access-block --bucket internal-app-audit-logs",
                terraform_fix="# Bucket is properly secured",
            ),
            compliance=["CIS-AWS-1.4:2.1.5", "NIST-800-53:AC-3"],
        ),
        Finding(
            check_id="s3_bucket_public_access",
            check_title="Ensure Amazon S3 Buckets Prohibit Public Access",
            service="s3",
            severity=Severity.CRITICAL,
            status=Status.ACCESS_DENIED,
            status_extended="Access Denied: s3:GetBucketPolicy / s3:GetPublicAccessBlock on 'legacy-vault-archive-restricted'. Scan incomplete for this resource.",
            resource_id="legacy-vault-archive-restricted",
            resource_arn="arn:aws:s3:::legacy-vault-archive-restricted",
            region="us-east-1",
            remediation=Remediation(
                description="CloudSentinel execution role was denied read permission to inspect bucket policy.",
                recommendation="Attach 'arn:aws:iam::aws:policy/SecurityAudit' to the CloudSentinel execution role.",
                cli_command="aws iam attach-role-policy --role-name CloudSentinelScannerRole --policy-arn arn:aws:iam::aws:policy/SecurityAudit",
                terraform_fix="resource \"aws_iam_role_policy_attachment\" \"audit\" {\n  role       = aws_iam_role.cloudsentinel.name\n  policy_arn = \"arn:aws:iam::aws:policy/SecurityAudit\"\n}",
            ),
            compliance=["CIS-AWS-1.4:2.1.5"],
        ),

        # --- CATEGORY 2: Risky IAM Policies ---
        Finding(
            check_id="iam_policy_allows_privilege_escalation",
            check_title="Ensure IAM Policies Do Not Allow Privilege Escalation",
            service="iam",
            severity=Severity.CRITICAL,
            status=Status.FAIL,
            status_extended="Policy 'DeveloperSelfProvisioningPolicy' grants 'iam:PassRole' combined with 'ec2:RunInstances' on wildcard resource '*', enabling full administrative takeover.",
            resource_id="DeveloperSelfProvisioningPolicy",
            resource_arn="arn:aws:iam::123456789012:policy/DeveloperSelfProvisioningPolicy",
            region="global",
            remediation=Remediation(
                description="Principals can launch an EC2 instance with an administrator role and retrieve instance metadata credentials.",
                recommendation="Restrict iam:PassRole to specific non-privileged role ARNs and enforce iam:PassedToService conditions.",
                cli_command="# Detach or scope down policy version\naws iam create-policy-version \\\n  --policy-arn arn:aws:iam::123456789012:policy/DeveloperSelfProvisioningPolicy \\\n  --policy-document file://scoped_policy.json \\\n  --set-as-default",
                terraform_fix="statement {\n  effect    = \"Allow\"\n  actions   = [\"iam:PassRole\"]\n  resources = [\"arn:aws:iam::123456789012:role/SpecificAppRoleOnly\"]\n  condition {\n    test     = \"StringEquals\"\n    variable = \"iam:PassedToService\"\n    values   = [\"ec2.amazonaws.com\"]\n  }\n}",
                documentation_url="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_passrole.html",
            ),
            compliance=["CIS-AWS-1.4:1.16", "NIST-800-53:AC-6"],
        ),
        Finding(
            check_id="iam_policy_wildcard_administrative_access",
            check_title="Ensure No IAM Policy Grants Full Administrative Wildcard (*:*)",
            service="iam",
            severity=Severity.CRITICAL,
            status=Status.FAIL,
            status_extended="Custom policy 'CustomAdminBypass' has Action '*' and Resource '*' without condition constraints.",
            resource_id="CustomAdminBypass",
            resource_arn="arn:aws:iam::123456789012:policy/CustomAdminBypass",
            region="global",
            remediation=Remediation(
                description="Overly permissive administrative policies violate least-privilege principles.",
                recommendation="Replace full administrative wildcards with role-based fine-grained permissions.",
                cli_command="aws iam delete-policy --policy-arn arn:aws:iam::123456789012:policy/CustomAdminBypass",
                terraform_fix="# Restrict actions to specific APIs\nstatement {\n  effect    = \"Allow\"\n  actions   = [\"s3:ListBucket\", \"s3:GetObject\"]\n  resources = [aws_s3_bucket.app.arn, \"${aws_s3_bucket.app.arn}/*\"]\n}",
            ),
            compliance=["CIS-AWS-1.4:1.22", "NIST-800-53:AC-2"],
        ),
        Finding(
            check_id="iam_policy_least_privilege",
            check_title="Ensure IAM Policies Follow Least Privilege",
            service="iam",
            severity=Severity.CRITICAL,
            status=Status.PASS,
            status_extended="Policy 'AppReadOnlyTelemetry' adheres to least privilege: strictly read-only actions scoped to specific telemetry resources.",
            resource_id="AppReadOnlyTelemetry",
            resource_arn="arn:aws:iam::123456789012:policy/AppReadOnlyTelemetry",
            region="global",
            remediation=Remediation(
                description="Policy is compliant with least privilege.",
                recommendation="Maintain current policy scoping.",
                cli_command="# Compliant policy",
                terraform_fix="# Compliant",
            ),
            compliance=["CIS-AWS-1.4:1.16"],
        ),

        # --- CATEGORY 3: Missing Encryption ---
        Finding(
            check_id="ebs_volume_encryption",
            check_title="Ensure EBS Volumes Are Encrypted at Rest",
            service="encryption",
            severity=Severity.HIGH,
            status=Status.FAIL,
            status_extended="EBS volume 'vol-0a1b2c3d4e5f67890' (attached to i-0123456789abcdef0) is NOT encrypted at rest.",
            resource_id="vol-0a1b2c3d4e5f67890",
            resource_arn="arn:aws:ec2:us-east-1:123456789012:volume/vol-0a1b2c3d4e5f67890",
            region="us-east-1",
            remediation=Remediation(
                description="Unencrypted volumes expose storage data to physical extraction or unauthorized snapshot restores.",
                recommendation="Enable EBS default account encryption and snapshot-copy-encrypt unencrypted volumes.",
                cli_command="aws ec2 enable-ebs-encryption-by-default --region us-east-1",
                terraform_fix="resource \"aws_ebs_encryption_by_default\" \"enabled\" {\n  enabled = true\n}\n\nresource \"aws_ebs_volume\" \"encrypted\" {\n  availability_zone = \"us-east-1a\"\n  size              = 40\n  encrypted         = true\n  kms_key_id        = \"alias/aws/ebs\"\n}",
                documentation_url="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html",
            ),
            compliance=["CIS-AWS-1.4:2.2.1", "NIST-800-53:SC-28", "HIPAA:164.312(a)(2)(iv)"],
        ),
        Finding(
            check_id="rds_instance_storage_encryption",
            check_title="Ensure RDS Database Instances Have Storage Encryption Enabled",
            service="encryption",
            severity=Severity.HIGH,
            status=Status.FAIL,
            status_extended="RDS instance 'customer-billing-db-01' is running unencrypted storage (StorageEncrypted=False).",
            resource_id="customer-billing-db-01",
            resource_arn="arn:aws:rds:us-east-1:123456789012:db:customer-billing-db-01",
            region="us-east-1",
            remediation=Remediation(
                description="Unencrypted database storage leaves databases vulnerable to data breaches if snapshots or disks are accessed.",
                recommendation="Snapshot the unencrypted DB, copy snapshot with KMS encryption enabled, and restore new instance.",
                cli_command="aws rds copy-db-snapshot \\\n  --source-db-snapshot-identifier unencrypted-snap \\\n  --target-db-snapshot-identifier encrypted-snap \\\n  --kms-key-id alias/aws/rds",
                terraform_fix="resource \"aws_db_instance\" \"encrypted_db\" {\n  identifier        = \"customer-billing-db-01\"\n  storage_encrypted = true\n  kms_key_id        = \"arn:aws:kms:us-east-1:123456789012:alias/aws/rds\"\n  # ... other attributes\n}",
            ),
            compliance=["CIS-AWS-1.4:2.3.1", "NIST-800-53:SC-28"],
        ),
        Finding(
            check_id="s3_bucket_default_encryption",
            check_title="Ensure S3 Buckets Enforce Server-Side Encryption (KMS or AES256)",
            service="encryption",
            severity=Severity.HIGH,
            status=Status.PASS,
            status_extended="Bucket 'prod-assets-cdn-origin' has SSE-KMS enabled with AWS KMS key.",
            resource_id="prod-assets-cdn-origin",
            resource_arn="arn:aws:s3:::prod-assets-cdn-origin",
            region="us-east-1",
            remediation=Remediation(
                description="Bucket is properly encrypted with KMS.",
                recommendation="Maintain default encryption policy.",
                cli_command="# Encrypted. Verification command:\naws s3api get-bucket-encryption --bucket prod-assets-cdn-origin",
                terraform_fix="# Compliant",
            ),
            compliance=["CIS-AWS-1.4:2.1.1", "NIST-800-53:SC-28"],
        ),

        # --- CATEGORY 4: Exposed Security Group Ports ---
        Finding(
            check_id="ec2_securitygroup_allow_ingress_port_22",
            check_title="Ensure No Security Groups Allow Ingress from 0.0.0.0/0 to SSH (Port 22)",
            service="ec2",
            severity=Severity.CRITICAL,
            status=Status.FAIL,
            status_extended="Security group 'sg-01a2b3c4d5e6f7g8h' (launch-wizard-1) allows 0.0.0.0/0 inbound on TCP port 22 (SSH).",
            resource_id="sg-01a2b3c4d5e6f7g8h",
            resource_arn="arn:aws:ec2:us-east-1:123456789012:security-group/sg-01a2b3c4d5e6f7g8h",
            region="us-east-1",
            remediation=Remediation(
                description="Port 22 open to 0.0.0.0/0 permits global brute-force and remote exploit attempts on SSH services.",
                recommendation="Remove 0.0.0.0/0 ingress rule. Restrict SSH to your corporate bastion or use AWS Systems Manager Session Manager.",
                cli_command="aws ec2 revoke-security-group-ingress \\\n  --group-id sg-01a2b3c4d5e6f7g8h \\\n  --protocol tcp --port 22 --cidr 0.0.0.0/0",
                terraform_fix="resource \"aws_security_group_rule\" \"ssh_restricted\" {\n  type              = \"ingress\"\n  from_port         = 22\n  to_port           = 22\n  protocol          = \"tcp\"\n  cidr_blocks       = [\"198.51.100.14/32\"] # Restricted corporate IP\n  security_group_id = aws_security_group.app.id\n}",
                documentation_url="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/authorizing-access-to-an-instance.html",
            ),
            compliance=["CIS-AWS-1.4:5.2", "NIST-800-53:AC-17", "PCI-DSS-4.0:1.3.1"],
        ),
        Finding(
            check_id="ec2_securitygroup_allow_ingress_port_3389",
            check_title="Ensure No Security Groups Allow Ingress from 0.0.0.0/0 to RDP (Port 3389)",
            service="ec2",
            severity=Severity.CRITICAL,
            status=Status.FAIL,
            status_extended="Security group 'sg-09z8y7x6w5v4u3t2s' (windows-bastion-sg) allows 0.0.0.0/0 inbound on TCP port 3389 (Microsoft Remote Desktop).",
            resource_id="sg-09z8y7x6w5v4u3t2s",
            resource_arn="arn:aws:ec2:us-east-1:123456789012:security-group/sg-09z8y7x6w5v4u3t2s",
            region="us-east-1",
            remediation=Remediation(
                description="Open RDP ports are actively targeted by ransomware operators and automated brute-force worms.",
                recommendation="Remove 0.0.0.0/0 and ::/0 rules. Enforce AWS Client VPN or SSM Fleet Manager for Windows access.",
                cli_command="aws ec2 revoke-security-group-ingress \\\n  --group-id sg-09z8y7x6w5v4u3t2s \\\n  --protocol tcp --port 3389 --cidr 0.0.0.0/0",
                terraform_fix="# Disallow open RDP - remove rule and use SSM Session Manager instead",
            ),
            compliance=["CIS-AWS-1.4:5.3", "NIST-800-53:AC-17"],
        ),
        Finding(
            check_id="ec2_securitygroup_safe_ingress",
            check_title="Ensure Security Group Ingress Is Restricted",
            service="ec2",
            severity=Severity.LOW,
            status=Status.PASS,
            status_extended="Security group 'sg-00112233445566778' (private-alb-sg) restricts ingress to private VPC subnet 10.100.0.0/16 and HTTPS port 443 only.",
            resource_id="sg-00112233445566778",
            resource_arn="arn:aws:ec2:us-east-1:123456789012:security-group/sg-00112233445566778",
            region="us-east-1",
            remediation=Remediation(
                description="Security group is compliant with network boundary policies.",
                recommendation="Maintain strict CIDR filtering.",
                cli_command="# Compliant SG",
                terraform_fix="# Compliant",
            ),
            compliance=["CIS-AWS-1.4:5.1"],
        ),
    ]


def get_mock_scan_response() -> Dict[str, Any]:
    """Return complete mock scan response with summary and score explanation."""
    findings = get_mock_findings()
    summary, score_explanation = compute_scan_summary(findings)
    return {
        "summary": summary.to_dict(),
        "findings": [f.to_dict() for f in findings],
        "score_explanation": score_explanation,
        "read_only_verified": True,
        "mode": "DEMO_ENVIRONMENT",
    }
