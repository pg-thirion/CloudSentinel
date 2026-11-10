"""
CloudSentinel S3 Public Access Detection Check
Evaluates S3 Bucket Public Access Block configuration, Bucket Policies, and ACLs
to detect unauthorized public exposure matching and beating Prowler standards.
"""
from typing import List, Dict, Any, Optional
import json
import botocore.exceptions
from .base import BaseCheck
from ..models import Finding, Severity, Status, Remediation


class S3PublicAccessCheck(BaseCheck):
    check_id: str = "s3_bucket_public_access"
    check_title: str = "Ensure S3 Buckets Prohibit Public Access via Block Settings, Policy, and ACL"
    service: str = "s3"
    severity: Severity = Severity.CRITICAL
    compliance: List[str] = [
        "CIS-AWS-1.4",
        "CIS-AWS-2.0",
        "PCI-DSS-v3.2.1",
        "SOC2",
        "NIST-800-53",
    ]

    PUBLIC_ACL_URIS = {
        "http://acs.amazonaws.com/groups/global/AllUsers",
        "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
    }

    RESTRICTIVE_CONDITION_KEYS = {
        "aws:principalaccount",
        "aws:principalarn",
        "aws:principalorgid",
        "aws:principalorgpaths",
        "aws:sourceaccount",
        "aws:sourcearn",
        "aws:sourceowner",
        "aws:sourcevpc",
        "aws:sourcevpce",
        "aws:sourceip",
        "aws:userid",
    }

    ACCESS_DENIED_CODES = (
        "AccessDenied",
        "AccessDeniedException",
        "UnauthorizedOperation",
        "ForbiddenException",
    )

    def _is_wildcard_principal(self, principal: Any) -> bool:
        """Evaluate if an IAM Principal includes wildcards granting broad access."""
        if principal == "*":
            return True
        if isinstance(principal, str) and principal.strip() == "*":
            return True
        if isinstance(principal, list):
            return any(self._is_wildcard_principal(p) for p in principal)
        if isinstance(principal, dict):
            for k, v in principal.items():
                if self._is_wildcard_principal(v):
                    return True
        return False

    def _has_restrictive_condition(self, condition: Any, effect: str = "Allow") -> bool:
        """
        Check if condition block constrains wildcard principal access to specific accounts/orgs/networks.
        When effect is Allow, negative operators (e.g. StringNotEquals, ArnNotEquals, NotIpAddress,
        StringNotEqualsIfExists) invert logic and grant access to the entire world except the specified target,
        so they are not restrictive.
        """
        if not isinstance(condition, dict) or not condition:
            return False

        for op, keys in condition.items():
            op_lower = op.lower().strip()
            # Reject negative operators when statement effect is Allow
            if effect.lower() == "allow" and "not" in op_lower:
                continue

            if isinstance(keys, dict):
                for key in keys.keys():
                    key_lower = key.lower().strip()
                    if key_lower in self.RESTRICTIVE_CONDITION_KEYS:
                        return True
                    if any(r_key in key_lower for r_key in self.RESTRICTIVE_CONDITION_KEYS):
                        return True
        return False

    def _build_remediation(self, bucket_name: str) -> Remediation:
        tf_name = bucket_name.replace("-", "_").replace(".", "_")
        return Remediation(
            description=f"Bucket '{bucket_name}' has public access enabled or lacks complete Public Access Block protection.",
            recommendation=(
                "Enable all four S3 Public Access Block settings (BlockPublicAcls, IgnorePublicAcls, "
                "BlockPublicPolicy, RestrictPublicBuckets) at the bucket level. "
                "Ensure bucket policies do not use wildcard Principals without restrictive conditions, "
                "and remove AllUsers / AuthenticatedUsers groups from bucket ACLs."
            ),
            cli_command=(
                f"aws s3api put-public-access-block \\\n"
                f"  --bucket {bucket_name} \\\n"
                f"  --public-access-block-configuration "
                f"\"BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true\""
            ),
            terraform_fix=(
                f'resource "aws_s3_bucket_public_access_block" "{tf_name}" {{\n'
                f'  bucket = "{bucket_name}"\n\n'
                f'  block_public_acls       = true\n'
                f'  block_public_policy     = true\n'
                f'  ignore_public_acls      = true\n'
                f'  restrict_public_buckets = true\n'
                f'}}'
            ),
            documentation_url="https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
        )

    def _build_access_denied_remediation(self, resource_name: str) -> Remediation:
        return Remediation(
            description=f"CloudSentinel scanner lacks IAM permissions to inspect S3 resource '{resource_name}'.",
            recommendation="Grant read-only permissions (s3:GetBucketPublicAccessBlock, s3:GetBucketPolicy, s3:GetBucketAcl, and s3:ListAllMyBuckets) to CloudSentinel IAM execution role.",
            cli_command="aws iam attach-role-policy --role-name <CloudSentinelScannerRole> --policy-arn arn:aws:iam::aws:policy/SecurityAudit",
            terraform_fix=(
                'resource "aws_iam_role_policy_attachment" "cloudsentinel_security_audit" {\n'
                '  role       = aws_iam_role.cloudsentinel_scanner.name\n'
                '  policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"\n'
                '}'
            ),
            documentation_url="https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-identity-based.html",
        )

    def run_check(self, session) -> List[Finding]:
        s3 = session.client("s3")
        findings: List[Finding] = []

        # 1. List Buckets
        try:
            response = s3.list_buckets()
        except botocore.exceptions.ClientError as e:
            err_code = e.response.get("Error", {}).get("Code", "ClientError")
            err_msg = e.response.get("Error", {}).get("Message", str(e))
            if err_code in self.ACCESS_DENIED_CODES:
                return [
                    Finding(
                        check_id=self.check_id,
                        check_title=self.check_title,
                        service=self.service,
                        severity=self.severity,
                        status=Status.ACCESS_DENIED,
                        status_extended=f"Access Denied listing S3 buckets: {err_code} - {err_msg}",
                        resource_id="arn:aws:s3:::*",
                        resource_arn="arn:aws:s3:::*",
                        region=getattr(session, "region_name", "global") or "global",
                        remediation=self._build_access_denied_remediation("*"),
                        compliance=self.compliance,
                    )
                ]
            raise

        buckets = response.get("Buckets", [])
        if not buckets:
            return []

        for b in buckets:
            bucket_name = b["Name"]
            bucket_arn = f"arn:aws:s3:::{bucket_name}"
            region = "us-east-1"

            # Check Bucket Region / Location (fallback gracefully if location query is denied)
            try:
                loc_resp = s3.get_bucket_location(Bucket=bucket_name)
                loc = loc_resp.get("LocationConstraint")
                if loc:
                    region = "eu-west-1" if loc == "EU" else loc
            except botocore.exceptions.ClientError as e:
                err_code = e.response.get("Error", {}).get("Code", "")
                if err_code in self.ACCESS_DENIED_CODES:
                    # Do not abort bucket audit if only location is denied; default to us-east-1 and continue
                    region = "us-east-1"
                else:
                    region = "us-east-1"

            # Use regional client to prevent 301 PermanentRedirect on non-us-east-1 buckets
            try:
                bucket_s3 = session.client("s3", region_name=region)
            except Exception:
                bucket_s3 = s3

            # Check Public Access Block
            pab_failures = []
            try:
                pab_resp = bucket_s3.get_public_access_block(Bucket=bucket_name)
                pab_config = pab_resp.get("PublicAccessBlockConfiguration", {})
                for flag in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"):
                    if not pab_config.get(flag, False):
                        pab_failures.append(f"{flag}=False")
            except botocore.exceptions.ClientError as e:
                err_code = e.response.get("Error", {}).get("Code", "")
                if err_code in self.ACCESS_DENIED_CODES:
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            check_title=self.check_title,
                            service=self.service,
                            severity=self.severity,
                            status=Status.ACCESS_DENIED,
                            status_extended=f"Access Denied checking Public Access Block on bucket '{bucket_name}': {err_code} - {e.response.get('Error', {}).get('Message', str(e))}",
                            resource_id=bucket_name,
                            resource_arn=bucket_arn,
                            region=region,
                            remediation=self._build_access_denied_remediation(bucket_name),
                            compliance=self.compliance,
                        )
                    )
                    continue
                elif err_code == "NoSuchPublicAccessBlockConfiguration":
                    pab_failures.append("Public Access Block is not configured")
                else:
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            check_title=self.check_title,
                            service=self.service,
                            severity=self.severity,
                            status=Status.ERROR,
                            status_extended=f"Error checking Public Access Block on bucket '{bucket_name}': {err_code} - {e.response.get('Error', {}).get('Message', str(e))}",
                            resource_id=bucket_name,
                            resource_arn=bucket_arn,
                            region=region,
                            remediation=self._build_remediation(bucket_name),
                            compliance=self.compliance,
                        )
                    )
                    continue

            # Check Bucket Policy
            public_policy_statements = []
            try:
                pol_resp = bucket_s3.get_bucket_policy(Bucket=bucket_name)
                policy_raw = pol_resp.get("Policy", "{}")
                policy_doc = json.loads(policy_raw) if isinstance(policy_raw, str) else policy_raw
                statements = policy_doc.get("Statement", [])
                if isinstance(statements, dict):
                    statements = [statements]

                for idx, stmt in enumerate(statements):
                    effect = stmt.get("Effect", "")
                    if effect.lower() == "allow":
                        principal = stmt.get("Principal")
                        if self._is_wildcard_principal(principal):
                            condition = stmt.get("Condition")
                            if not self._has_restrictive_condition(condition, effect=effect):
                                sid = stmt.get("Sid", f"Statement[{idx}]")
                                public_policy_statements.append(sid)
            except botocore.exceptions.ClientError as e:
                err_code = e.response.get("Error", {}).get("Code", "")
                if err_code in self.ACCESS_DENIED_CODES:
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            check_title=self.check_title,
                            service=self.service,
                            severity=self.severity,
                            status=Status.ACCESS_DENIED,
                            status_extended=f"Access Denied checking policy on bucket '{bucket_name}': {err_code} - {e.response.get('Error', {}).get('Message', str(e))}",
                            resource_id=bucket_name,
                            resource_arn=bucket_arn,
                            region=region,
                            remediation=self._build_access_denied_remediation(bucket_name),
                            compliance=self.compliance,
                        )
                    )
                    continue
                elif err_code == "NoSuchBucketPolicy":
                    pass
                else:
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            check_title=self.check_title,
                            service=self.service,
                            severity=self.severity,
                            status=Status.ERROR,
                            status_extended=f"Error checking policy on bucket '{bucket_name}': {err_code} - {e.response.get('Error', {}).get('Message', str(e))}",
                            resource_id=bucket_name,
                            resource_arn=bucket_arn,
                            region=region,
                            remediation=self._build_remediation(bucket_name),
                            compliance=self.compliance,
                        )
                    )
                    continue

            # Check Bucket ACL
            public_acl_grants = []
            try:
                acl_resp = bucket_s3.get_bucket_acl(Bucket=bucket_name)
                grants = acl_resp.get("Grants", [])
                for grant in grants:
                    grantee = grant.get("Grantee", {})
                    uri = grantee.get("URI", "")
                    if uri in self.PUBLIC_ACL_URIS:
                        perm = grant.get("Permission", "UNKNOWN")
                        group_name = "AllUsers" if "AllUsers" in uri else "AuthenticatedUsers"
                        public_acl_grants.append(f"{group_name} ({perm})")
            except botocore.exceptions.ClientError as e:
                err_code = e.response.get("Error", {}).get("Code", "")
                if err_code in self.ACCESS_DENIED_CODES:
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            check_title=self.check_title,
                            service=self.service,
                            severity=self.severity,
                            status=Status.ACCESS_DENIED,
                            status_extended=f"Access Denied checking ACL on bucket '{bucket_name}': {err_code} - {e.response.get('Error', {}).get('Message', str(e))}",
                            resource_id=bucket_name,
                            resource_arn=bucket_arn,
                            region=region,
                            remediation=self._build_access_denied_remediation(bucket_name),
                            compliance=self.compliance,
                        )
                    )
                    continue
                else:
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            check_title=self.check_title,
                            service=self.service,
                            severity=self.severity,
                            status=Status.ERROR,
                            status_extended=f"Error checking ACL on bucket '{bucket_name}': {err_code} - {e.response.get('Error', {}).get('Message', str(e))}",
                            resource_id=bucket_name,
                            resource_arn=bucket_arn,
                            region=region,
                            remediation=self._build_remediation(bucket_name),
                            compliance=self.compliance,
                        )
                    )
                    continue

            # Consolidate Findings
            vulnerabilities = []
            if pab_failures:
                vulnerabilities.append(f"Public Access Block incomplete: {', '.join(pab_failures)}")
            if public_policy_statements:
                vulnerabilities.append(f"Public Bucket Policy allows wildcard access in statements: {', '.join(public_policy_statements)}")
            if public_acl_grants:
                vulnerabilities.append(f"Public ACL grants detected: {', '.join(public_acl_grants)}")

            if vulnerabilities:
                status = Status.FAIL
                status_extended = f"Bucket '{bucket_name}' has public access vulnerabilities: " + "; ".join(vulnerabilities)
            else:
                status = Status.PASS
                status_extended = f"Bucket '{bucket_name}' is secure: Public Access Block is fully enabled, bucket policy is restricted, and ACLs contain no public grants."

            findings.append(
                Finding(
                    check_id=self.check_id,
                    check_title=self.check_title,
                    service=self.service,
                    severity=self.severity,
                    status=status,
                    status_extended=status_extended,
                    resource_id=bucket_name,
                    resource_arn=bucket_arn,
                    region=region,
                    remediation=self._build_remediation(bucket_name),
                    compliance=self.compliance,
                )
            )

        return findings
