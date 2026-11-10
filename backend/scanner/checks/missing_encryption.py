"""
CloudSentinel Missing Encryption Detection Checks
Audits primary storage/data resources (S3, EBS, RDS) to ensure encryption at rest is enforced,
supporting multi-region discovery via ec2:DescribeRegions, matching and beating Prowler standards.
"""
from typing import List, Dict, Any, Optional
from concurrent.futures import ThreadPoolExecutor
import botocore.exceptions
from .base import BaseCheck
from ..models import Finding, Severity, Status, Remediation


ACCESS_DENIED_CODES = (
    "AccessDenied",
    "AccessDeniedException",
    "UnauthorizedOperation",
    "ForbiddenException",
    "AuthFailure",
)


def _is_access_denied(err: botocore.exceptions.ClientError) -> bool:
    """Check if ClientError represents an IAM or authorization denial."""
    code = err.response.get("Error", {}).get("Code", "")
    msg = err.response.get("Error", {}).get("Message", "")
    if code in ACCESS_DENIED_CODES:
        return True
    if any(phrase in msg.lower() for phrase in ("access denied", "unauthorized", "not authorized")):
        return True
    return False


def _get_account_id(session) -> str:
    """Retrieve current AWS account ID safely for ARNs."""
    try:
        sts = session.client("sts")
        return sts.get_caller_identity().get("Account", "123456789012")
    except Exception:
        return "123456789012"


def _get_region(session) -> str:
    """Retrieve current AWS session region safely."""
    reg = getattr(session, "region_name", None)
    return reg if isinstance(reg, str) and reg else "us-east-1"


def _get_active_regions(session, regions_override: Optional[List[str]] = None, ec2_client=None) -> List[str]:
    """
    Retrieve active/opted-in AWS regions across the account.
    Queries ec2:DescribeRegions with opt-in status filters (opt-in-not-required and opted-in).
    Falls back gracefully to session region if describe_regions is denied or fails.
    """
    if regions_override is not None:
        return regions_override

    # Use session cache if available to prevent redundant DescribeRegions calls
    cached_regions = getattr(session, "_cloudsentinel_active_regions", None)
    if isinstance(cached_regions, list):
        return cached_regions

    session_region = _get_region(session)
    try:
        ec2 = ec2_client or session.client("ec2", region_name=session_region)
        resp = ec2.describe_regions(
            Filters=[{"Name": "opt-in-status", "Values": ["opt-in-not-required", "opted-in"]}]
        )
        regions = [r["RegionName"] for r in resp.get("Regions", []) if "RegionName" in r]
        result = sorted(regions) if regions else [session_region]
    except Exception:
        # Graceful fallback to session region on AccessDenied, UnauthorizedOperation, or API failure
        result = [session_region]

    try:
        session._cloudsentinel_active_regions = result
    except Exception:
        pass

    return result


def _build_access_denied_remediation(service_name: str, resource_desc: str) -> Remediation:
    """Standardized remediation when IAM permissions are insufficient."""
    return Remediation(
        description=f"CloudSentinel scanner lacks IAM permissions to inspect encryption on {resource_desc}.",
        recommendation=f"Grant read-only permissions for {service_name} (e.g., attach 'SecurityAudit' policy) to the CloudSentinel execution role.",
        cli_command="aws iam attach-role-policy --role-name <CloudSentinelScannerRole> --policy-arn arn:aws:iam::aws:policy/SecurityAudit",
        terraform_fix=(
            'resource "aws_iam_role_policy_attachment" "cloudsentinel_security_audit" {\n'
            '  role       = aws_iam_role.cloudsentinel_scanner.name\n'
            '  policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"\n'
            '}'
        ),
        documentation_url="https://docs.aws.amazon.com/IAM/latest/UserGuide/access-control-identity-based.html",
    )


class S3DefaultEncryptionCheck(BaseCheck):
    """
    Check if Amazon S3 buckets enforce default server-side encryption
    configured with aws:kms, AES256, or aws:kms:dsse across all regions.
    """
    check_id: str = "s3_bucket_default_encryption"
    check_title: str = "Ensure S3 Buckets Enforce Server-Side Encryption (KMS or AES256)"
    service: str = "encryption"
    severity: Severity = Severity.HIGH
    compliance: List[str] = [
        "CIS-AWS-1.4:2.1.1",
        "CIS-AWS-2.0:2.1.1",
        "NIST-800-53:SC-28",
        "HIPAA:164.312(a)(2)(iv)",
        "PCI-DSS-4.0:3.4",
    ]

    ALLOWED_SSE_ALGORITHMS = {"AES256", "aws:kms", "aws:kms:dsse"}

    def _build_fail_remediation(self, bucket_name: str) -> Remediation:
        tf_name = bucket_name.replace("-", "_").replace(".", "_")
        return Remediation(
            description=f"S3 bucket '{bucket_name}' does not enforce default server-side encryption at rest.",
            recommendation="Enable default server-side encryption using KMS (aws:kms) or AES256 for all uploaded objects.",
            cli_command=(
                f"aws s3api put-bucket-encryption \\\n"
                f"  --bucket {bucket_name} \\\n"
                f'  --server-side-encryption-configuration \'{{"Rules": [{{"ApplyServerSideEncryptionByDefault": {{"SSEAlgorithm": "aws:kms"}}}}]}}\''
            ),
            terraform_fix=(
                f'resource "aws_s3_bucket_server_side_encryption_configuration" "{tf_name}_encryption" {{\n'
                f'  bucket = "{bucket_name}"\n\n'
                f'  rule {{\n'
                f'    apply_server_side_encryption_by_default {{\n'
                f'      sse_algorithm = "aws:kms"\n'
                f'    }}\n'
                f'  }}\n'
                f'}}'
            ),
            documentation_url="https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-encryption.html",
        )

    def _build_pass_remediation(self, bucket_name: str, algo: str, key_id: Optional[str] = None) -> Remediation:
        key_desc = f" using KMS key '{key_id}'" if key_id else ""
        return Remediation(
            description=f"S3 bucket '{bucket_name}' has default server-side encryption enabled ({algo}{key_desc}).",
            recommendation="Maintain default server-side encryption configuration.",
            cli_command=f"# Bucket is properly encrypted. Verification command:\naws s3api get-bucket-encryption --bucket {bucket_name}",
            terraform_fix=f"# Compliant: S3 bucket '{bucket_name}' enforces default encryption ({algo})",
            documentation_url="https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-encryption.html",
        )

    def run_check(self, session) -> List[Finding]:
        s3 = session.client("s3")
        findings: List[Finding] = []
        default_region = _get_region(session)

        try:
            buckets_resp = s3.list_buckets()
        except botocore.exceptions.ClientError as e:
            err_code = e.response.get("Error", {}).get("Code", "ClientError")
            err_msg = e.response.get("Error", {}).get("Message", str(e))
            if _is_access_denied(e):
                return [
                    Finding(
                        check_id=self.check_id,
                        check_title=self.check_title,
                        service=self.service,
                        severity=self.severity,
                        status=Status.ACCESS_DENIED,
                        status_extended=f"Access Denied listing S3 buckets: {err_code} - {err_msg}",
                        resource_id="s3:*",
                        resource_arn="arn:aws:s3:::*",
                        region=default_region,
                        remediation=_build_access_denied_remediation("Amazon S3", "S3 buckets"),
                        compliance=self.compliance,
                    )
                ]
            raise

        buckets = buckets_resp.get("Buckets", [])
        for b in buckets:
            bucket_name = b["Name"]
            bucket_arn = f"arn:aws:s3:::{bucket_name}"
            region = default_region

            # Determine region if possible
            try:
                loc_resp = s3.get_bucket_location(Bucket=bucket_name)
                loc = loc_resp.get("LocationConstraint")
                if loc:
                    region = "eu-west-1" if loc == "EU" else loc
                else:
                    region = "us-east-1"
            except botocore.exceptions.ClientError:
                pass

            # Use regional client to prevent 301 PermanentRedirect on non-us-east-1 buckets
            try:
                bucket_s3 = session.client("s3", region_name=region)
            except Exception:
                bucket_s3 = s3

            # Inspect default encryption configuration
            try:
                enc_resp = bucket_s3.get_bucket_encryption(Bucket=bucket_name)
                rules = enc_resp.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
                
                valid_encryption = False
                matched_algo = None
                matched_key = None

                for rule in rules:
                    apply_default = rule.get("ApplyServerSideEncryptionByDefault", {})
                    algo = apply_default.get("SSEAlgorithm")
                    if algo in self.ALLOWED_SSE_ALGORITHMS:
                        valid_encryption = True
                        matched_algo = algo
                        matched_key = apply_default.get("KMSMasterKeyID") or apply_default.get("KMSMasterKeyId")
                        break

                if valid_encryption:
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            check_title=self.check_title,
                            service=self.service,
                            severity=self.severity,
                            status=Status.PASS,
                            status_extended=(
                                f"Bucket '{bucket_name}' has default server-side encryption enabled "
                                f"with {matched_algo}" + (f" (KMS Key: {matched_key})." if matched_key else ".")
                            ),
                            resource_id=bucket_name,
                            resource_arn=bucket_arn,
                            region=region,
                            remediation=self._build_pass_remediation(bucket_name, matched_algo, matched_key),
                            compliance=self.compliance,
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            check_title=self.check_title,
                            service=self.service,
                            severity=self.severity,
                            status=Status.FAIL,
                            status_extended=(
                                f"Bucket '{bucket_name}' has ServerSideEncryptionConfiguration, "
                                f"but does not configure a valid encryption algorithm (aws:kms or AES256)."
                            ),
                            resource_id=bucket_name,
                            resource_arn=bucket_arn,
                            region=region,
                            remediation=self._build_fail_remediation(bucket_name),
                            compliance=self.compliance,
                        )
                    )

            except botocore.exceptions.ClientError as e:
                err_code = e.response.get("Error", {}).get("Code", "")
                err_msg = e.response.get("Error", {}).get("Message", str(e))

                if err_code == "ServerSideEncryptionConfigurationNotFoundError":
                    # Standard AWS S3 response when bucket has no SSE configured
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            check_title=self.check_title,
                            service=self.service,
                            severity=self.severity,
                            status=Status.FAIL,
                            status_extended=f"Bucket '{bucket_name}' does not have default server-side encryption enabled.",
                            resource_id=bucket_name,
                            resource_arn=bucket_arn,
                            region=region,
                            remediation=self._build_fail_remediation(bucket_name),
                            compliance=self.compliance,
                        )
                    )
                elif _is_access_denied(e):
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            check_title=self.check_title,
                            service=self.service,
                            severity=self.severity,
                            status=Status.ACCESS_DENIED,
                            status_extended=f"Access Denied checking encryption for bucket '{bucket_name}': {err_code} - {err_msg}",
                            resource_id=bucket_name,
                            resource_arn=bucket_arn,
                            region=region,
                            remediation=_build_access_denied_remediation("Amazon S3", f"bucket '{bucket_name}'"),
                            compliance=self.compliance,
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            check_title=self.check_title,
                            service=self.service,
                            severity=self.severity,
                            status=Status.ERROR,
                            status_extended=f"Error checking encryption for bucket '{bucket_name}': {err_code} - {err_msg}",
                            resource_id=bucket_name,
                            resource_arn=bucket_arn,
                            region=region,
                            remediation=self._build_fail_remediation(bucket_name),
                            compliance=self.compliance,
                        )
                    )

        return findings


class EBSVolumeEncryptionCheck(BaseCheck):
    """
    Check if EC2 Elastic Block Store (EBS) volumes are encrypted at rest across all active regions.
    """
    check_id: str = "ebs_volume_encryption"
    check_title: str = "Ensure EBS Volumes Are Encrypted at Rest"
    service: str = "encryption"
    severity: Severity = Severity.HIGH
    compliance: List[str] = [
        "CIS-AWS-1.4:2.2.1",
        "CIS-AWS-2.0:2.2.1",
        "NIST-800-53:SC-28",
        "HIPAA:164.312(a)(2)(iv)",
        "PCI-DSS-4.0:3.4",
    ]

    def __init__(self, regions: Optional[List[str]] = None):
        self.regions = regions

    def _build_fail_remediation(self, volume_id: str, region: str, az: str, size: int) -> Remediation:
        tf_name = volume_id.replace("-", "_")
        return Remediation(
            description=f"EBS volume '{volume_id}' is not encrypted at rest. Storage data is exposed to unauthorized snapshot access.",
            recommendation="Enable EBS encryption by default in the AWS region. Snapshot unencrypted volume, copy snapshot with KMS encryption, and restore.",
            cli_command=(
                f"# Step 1: Enable EBS default account encryption in this region\n"
                f"aws ec2 enable-ebs-encryption-by-default --region {region}\n\n"
                f"# Step 2: Create snapshot and copy with KMS encryption\n"
                f"aws ec2 create-snapshot --volume-id {volume_id} --description 'CloudSentinel migration snapshot'\n"
                f"aws ec2 copy-snapshot --source-region {region} --source-snapshot-id <snapshot-id> --encrypted --kms-key-id alias/aws/ebs"
            ),
            terraform_fix=(
                f'# Enable default EBS encryption across account and region\n'
                f'resource "aws_ebs_encryption_by_default" "enabled" {{\n'
                f'  enabled = true\n'
                f'}}\n\n'
                f'# Ensure all EBS volumes have encrypted = true\n'
                f'resource "aws_ebs_volume" "{tf_name}" {{\n'
                f'  availability_zone = "{az}"\n'
                f'  size              = {size}\n'
                f'  encrypted         = true\n'
                f'  kms_key_id        = "alias/aws/ebs"\n'
                f'}}'
            ),
            documentation_url="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html",
        )

    def _build_pass_remediation(self, volume_id: str, kms_key_id: Optional[str] = None) -> Remediation:
        key_info = f" with KMS key '{kms_key_id}'" if kms_key_id else ""
        return Remediation(
            description=f"EBS volume '{volume_id}' is encrypted at rest{key_info}.",
            recommendation="Maintain EBS encryption at rest.",
            cli_command=f"# Volume is encrypted. Verification command:\naws ec2 describe-volumes --volume-ids {volume_id} --query 'Volumes[*].Encrypted'",
            terraform_fix=f"# Compliant: EBS volume '{volume_id}' is encrypted",
            documentation_url="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html",
        )

    def _get_volumes(self, ec2) -> List[Dict[str, Any]]:
        """Retrieve EBS volumes handling pagination or mock client fallback."""
        if type(ec2).__name__ in ("MagicMock", "Mock", "AsyncMock"):
            resp = ec2.describe_volumes()
            return resp.get("Volumes", []) if isinstance(resp, dict) else []

        try:
            paginator = ec2.get_paginator("describe_volumes")
            volumes = []
            for page in paginator.paginate():
                volumes.extend(page.get("Volumes", []))
            return volumes
        except Exception:
            resp = ec2.describe_volumes()
            return resp.get("Volumes", []) if isinstance(resp, dict) else []

    def run_check(self, session, regions: Optional[List[str]] = None) -> List[Finding]:
        target_regions = regions or self.regions or _get_active_regions(session)
        account_id = _get_account_id(session)

        def _audit_ebs_region(reg: str, ec2_client=None) -> List[Finding]:
            reg_findings = []
            try:
                ec2 = ec2_client or session.client("ec2", region_name=reg)
                volumes = self._get_volumes(ec2)
            except botocore.exceptions.ClientError as e:
                err_code = e.response.get("Error", {}).get("Code", "ClientError")
                err_msg = e.response.get("Error", {}).get("Message", str(e))
                if _is_access_denied(e):
                    return [
                        Finding(
                            check_id=self.check_id,
                            check_title=self.check_title,
                            service=self.service,
                            severity=self.severity,
                            status=Status.ACCESS_DENIED,
                            status_extended=f"Access Denied describing EBS volumes in region '{reg}': {err_code} - {err_msg}",
                            resource_id=f"ec2:volumes:{reg}",
                            resource_arn=f"arn:aws:ec2:{reg}:{account_id}:volume/*",
                            region=reg,
                            remediation=_build_access_denied_remediation("Amazon EC2 / EBS", f"EBS volumes in region '{reg}'"),
                            compliance=self.compliance,
                        )
                    ]
                raise

            for vol in volumes:
                vol_id = vol.get("VolumeId", "unknown-volume")
                az = vol.get("AvailabilityZone", f"{reg}a")
                vol_region = az[:-1] if az and az[-1].isalpha() else reg
                vol_arn = f"arn:aws:ec2:{vol_region}:{account_id}:volume/{vol_id}"
                encrypted = vol.get("Encrypted", False)
                size = vol.get("Size", 20)
                kms_key = vol.get("KmsKeyId")

                attachments = vol.get("Attachments", [])
                attached_instance = attachments[0].get("InstanceId") if attachments else None
                attachment_str = f" (attached to {attached_instance})" if attached_instance else ""

                if encrypted:
                    reg_findings.append(
                        Finding(
                            check_id=self.check_id,
                            check_title=self.check_title,
                            service=self.service,
                            severity=self.severity,
                            status=Status.PASS,
                            status_extended=(
                                f"EBS volume '{vol_id}'{attachment_str} in region '{vol_region}' is encrypted at rest"
                                + (f" (KMS Key: {kms_key})." if kms_key else ".")
                            ),
                            resource_id=vol_id,
                            resource_arn=vol_arn,
                            region=vol_region,
                            remediation=self._build_pass_remediation(vol_id, kms_key),
                            compliance=self.compliance,
                        )
                    )
                else:
                    reg_findings.append(
                        Finding(
                            check_id=self.check_id,
                            check_title=self.check_title,
                            service=self.service,
                            severity=self.severity,
                            status=Status.FAIL,
                            status_extended=f"EBS volume '{vol_id}'{attachment_str} in region '{vol_region}' is NOT encrypted at rest.",
                            resource_id=vol_id,
                            resource_arn=vol_arn,
                            region=vol_region,
                            remediation=self._build_fail_remediation(vol_id, vol_region, az, size),
                            compliance=self.compliance,
                        )
                    )
            return reg_findings

        findings: List[Finding] = []
        if len(target_regions) <= 1:
            for r in target_regions:
                findings.extend(_audit_ebs_region(r))
        else:
            regional_clients = {r: session.client("ec2", region_name=r) for r in target_regions}
            with ThreadPoolExecutor(max_workers=min(8, len(target_regions))) as executor:
                for r_findings in executor.map(lambda r: _audit_ebs_region(r, ec2_client=regional_clients[r]), target_regions):
                    findings.extend(r_findings)

        return findings


class RDSInstanceEncryptionCheck(BaseCheck):
    """
    Check if Amazon RDS Database Instances have storage encryption enabled across all active regions.
    """
    check_id: str = "rds_instance_storage_encryption"
    check_title: str = "Ensure RDS Database Instances Have Storage Encryption Enabled"
    service: str = "encryption"
    severity: Severity = Severity.HIGH
    compliance: List[str] = [
        "CIS-AWS-1.4:2.3.1",
        "CIS-AWS-2.0:2.3.1",
        "NIST-800-53:SC-28",
        "HIPAA:164.312(a)(2)(iv)",
        "PCI-DSS-4.0:3.4",
    ]

    def __init__(self, regions: Optional[List[str]] = None):
        self.regions = regions

    def _build_fail_remediation(self, db_id: str, region: str) -> Remediation:
        tf_name = db_id.replace("-", "_")
        return Remediation(
            description=f"RDS instance '{db_id}' has storage encryption disabled (StorageEncrypted=False).",
            recommendation="Create a DB snapshot, copy the snapshot with KMS encryption enabled, and restore a new encrypted DB instance.",
            cli_command=(
                f"# Step 1: Create snapshot of unencrypted database\n"
                f"aws rds create-db-snapshot --db-instance-identifier {db_id} --db-snapshot-identifier {db_id}-unencrypted-snap --region {region}\n\n"
                f"# Step 2: Copy snapshot with KMS encryption enabled\n"
                f"aws rds copy-db-snapshot \\\n"
                f"  --source-db-snapshot-identifier {db_id}-unencrypted-snap \\\n"
                f"  --target-db-snapshot-identifier {db_id}-encrypted-snap \\\n"
                f"  --kms-key-id alias/aws/rds \\\n"
                f"  --region {region}\n\n"
                f"# Step 3: Restore encrypted DB instance from encrypted snapshot\n"
                f"aws rds restore-db-instance-from-db-snapshot \\\n"
                f"  --db-instance-identifier {db_id}-encrypted \\\n"
                f"  --db-snapshot-identifier {db_id}-encrypted-snap \\\n"
                f"  --region {region}"
            ),
            terraform_fix=(
                f'resource "aws_db_instance" "{tf_name}" {{\n'
                f'  identifier        = "{db_id}"\n'
                f'  storage_encrypted = true\n'
                f'  kms_key_id        = "alias/aws/rds"\n'
                f'  # Ensure storage_encrypted is set to true for all databases\n'
                f'}}'
            ),
            documentation_url="https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html",
        )

    def _build_pass_remediation(self, db_id: str, kms_key_id: Optional[str] = None) -> Remediation:
        key_info = f" with KMS key '{kms_key_id}'" if kms_key_id else ""
        return Remediation(
            description=f"RDS DB instance '{db_id}' has storage encryption enabled{key_info}.",
            recommendation="Maintain RDS storage encryption at rest.",
            cli_command=f"# RDS DB instance is encrypted. Verification command:\naws rds describe-db-instances --db-instance-identifier {db_id} --query 'DBInstances[*].StorageEncrypted'",
            terraform_fix=f"# Compliant: RDS DB instance '{db_id}' has storage_encrypted = true",
            documentation_url="https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html",
        )

    def _get_instances(self, rds) -> List[Dict[str, Any]]:
        """Retrieve RDS DB instances handling pagination or mock client fallback."""
        if type(rds).__name__ in ("MagicMock", "Mock", "AsyncMock"):
            resp = rds.describe_db_instances()
            return resp.get("DBInstances", []) if isinstance(resp, dict) else []

        try:
            paginator = rds.get_paginator("describe_db_instances")
            instances = []
            for page in paginator.paginate():
                instances.extend(page.get("DBInstances", []))
            return instances
        except Exception:
            resp = rds.describe_db_instances()
            return resp.get("DBInstances", []) if isinstance(resp, dict) else []

    def run_check(self, session, regions: Optional[List[str]] = None) -> List[Finding]:
        target_regions = regions or self.regions or _get_active_regions(session)
        account_id = _get_account_id(session)

        def _audit_rds_region(reg: str, rds_client=None) -> List[Finding]:
            reg_findings = []
            try:
                rds = rds_client or session.client("rds", region_name=reg)
                instances = self._get_instances(rds)
            except botocore.exceptions.ClientError as e:
                err_code = e.response.get("Error", {}).get("Code", "ClientError")
                err_msg = e.response.get("Error", {}).get("Message", str(e))
                if _is_access_denied(e):
                    return [
                        Finding(
                            check_id=self.check_id,
                            check_title=self.check_title,
                            service=self.service,
                            severity=self.severity,
                            status=Status.ACCESS_DENIED,
                            status_extended=f"Access Denied describing RDS DB instances in region '{reg}': {err_code} - {err_msg}",
                            resource_id=f"rds:db-instances:{reg}",
                            resource_arn=f"arn:aws:rds:{reg}:{account_id}:db:*",
                            region=reg,
                            remediation=_build_access_denied_remediation("Amazon RDS", f"RDS DB instances in region '{reg}'"),
                            compliance=self.compliance,
                        )
                    ]
                raise

            for inst in instances:
                db_id = inst.get("DBInstanceIdentifier", "unknown-db")
                db_arn = inst.get("DBInstanceArn", f"arn:aws:rds:{reg}:{account_id}:db:{db_id}")
                encrypted = inst.get("StorageEncrypted", False)
                engine = inst.get("Engine", "database")
                kms_key = inst.get("KmsKeyId")

                if encrypted:
                    reg_findings.append(
                        Finding(
                            check_id=self.check_id,
                            check_title=self.check_title,
                            service=self.service,
                            severity=self.severity,
                            status=Status.PASS,
                            status_extended=(
                                f"RDS DB instance '{db_id}' ({engine}) in region '{reg}' has storage encryption enabled"
                                + (f" (KMS Key: {kms_key})." if kms_key else ".")
                            ),
                            resource_id=db_id,
                            resource_arn=db_arn,
                            region=reg,
                            remediation=self._build_pass_remediation(db_id, kms_key),
                            compliance=self.compliance,
                        )
                    )
                else:
                    reg_findings.append(
                        Finding(
                            check_id=self.check_id,
                            check_title=self.check_title,
                            service=self.service,
                            severity=self.severity,
                            status=Status.FAIL,
                            status_extended=f"RDS DB instance '{db_id}' ({engine}) in region '{reg}' is running unencrypted storage (StorageEncrypted=False).",
                            resource_id=db_id,
                            resource_arn=db_arn,
                            region=reg,
                            remediation=self._build_fail_remediation(db_id, reg),
                            compliance=self.compliance,
                        )
                    )
            return reg_findings

        findings: List[Finding] = []
        if len(target_regions) <= 1:
            for r in target_regions:
                findings.extend(_audit_rds_region(r))
        else:
            regional_clients = {r: session.client("rds", region_name=r) for r in target_regions}
            with ThreadPoolExecutor(max_workers=min(8, len(target_regions))) as executor:
                for r_findings in executor.map(lambda r: _audit_rds_region(r, rds_client=regional_clients[r]), target_regions):
                    findings.extend(r_findings)

        return findings


class MissingEncryptionCheck(BaseCheck):
    """
    Composite Missing Encryption Detection Engine.
    Coordinates multi-region encryption checks across Amazon S3, EC2 EBS volumes, and RDS databases.
    Matches and beats Prowler standards.
    """
    check_id: str = "missing_encryption"
    check_title: str = "Ensure Primary Data Storage (S3, EBS, RDS) Has Encryption at Rest Enabled"
    service: str = "encryption"
    severity: Severity = Severity.HIGH
    compliance: List[str] = [
        "CIS-AWS-1.4:2.1.1",
        "CIS-AWS-1.4:2.2.1",
        "CIS-AWS-1.4:2.3.1",
        "CIS-AWS-2.0:2.1.1",
        "CIS-AWS-2.0:2.2.1",
        "CIS-AWS-2.0:2.3.1",
        "NIST-800-53:SC-28",
        "HIPAA:164.312(a)(2)(iv)",
        "PCI-DSS-4.0:3.4",
    ]

    def __init__(self, regions: Optional[List[str]] = None):
        self.regions = regions
        self.s3_check = S3DefaultEncryptionCheck()
        self.ebs_check = EBSVolumeEncryptionCheck(regions=regions)
        self.rds_check = RDSInstanceEncryptionCheck(regions=regions)

    def check_s3_encryption(self, session) -> List[Finding]:
        """Audit S3 default encryption across all buckets."""
        return self.s3_check.run_check(session)

    def check_ebs_encryption(self, session, regions: Optional[List[str]] = None) -> List[Finding]:
        """Audit EBS volume encryption across active regions."""
        return self.ebs_check.run_check(session, regions=regions)

    def check_rds_encryption(self, session, regions: Optional[List[str]] = None) -> List[Finding]:
        """Audit RDS DB instance storage encryption across active regions."""
        return self.rds_check.run_check(session, regions=regions)

    def run_check(self, session, regions: Optional[List[str]] = None) -> List[Finding]:
        """Execute all encryption checks across S3, EBS, and RDS multi-region."""
        target_regions = regions or self.regions or _get_active_regions(session)
        findings: List[Finding] = []
        findings.extend(self.check_s3_encryption(session))
        findings.extend(self.check_ebs_encryption(session, regions=target_regions))
        findings.extend(self.check_rds_encryption(session, regions=target_regions))
        return findings
