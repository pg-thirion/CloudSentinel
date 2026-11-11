"""
CloudSentinel Exposed Security Groups Check
Detects unrestricted ingress (0.0.0.0/0 or ::/0) on sensitive management ports (SSH 22, RDP 3389),
database ports (MySQL 3306, PostgreSQL 5432, MSSQL 1433, MongoDB 27017), and all-traffic rules (-1).
Compliant with CIS AWS Benchmark 1.4 (5.2, 5.3), NIST 800-53 AC-17, and PCI-DSS 4.0 1.3.1.
"""
from typing import List, Dict, Any, Optional
from concurrent.futures import ThreadPoolExecutor
import botocore.exceptions
from .base import BaseCheck
from ..models import Finding, Severity, Status, Remediation

# Sensitive ports and their metadata
SENSITIVE_MANAGEMENT_PORTS: Dict[int, Dict[str, Any]] = {
    22: {
        "name": "SSH",
        "protocol": "tcp",
        "severity": Severity.CRITICAL,
        "compliance": ["CIS-AWS-1.4:5.2", "NIST-800-53:AC-17", "PCI-DSS-4.0:1.3.1"],
        "check_id": "ec2_securitygroup_allow_ingress_port_22",
        "check_title": "Ensure No Security Groups Allow Ingress from 0.0.0.0/0 to SSH (Port 22)",
    },
    3389: {
        "name": "RDP",
        "protocol": "tcp",  # also udp in some environments
        "severity": Severity.CRITICAL,
        "compliance": ["CIS-AWS-1.4:5.3", "NIST-800-53:AC-17", "PCI-DSS-4.0:1.3.1"],
        "check_id": "ec2_securitygroup_allow_ingress_port_3389",
        "check_title": "Ensure No Security Groups Allow Ingress from 0.0.0.0/0 to RDP (Port 3389)",
    },
}

DATABASE_PORTS: Dict[int, Dict[str, Any]] = {
    3306: {
        "name": "MySQL/MariaDB",
        "protocol": "tcp",
        "severity": Severity.HIGH,
        "compliance": ["PCI-DSS-4.0:1.3.1", "NIST-800-53:AC-17"],
        "check_id": "ec2_securitygroup_allow_ingress_db_ports",
        "check_title": "Ensure No Security Groups Allow Ingress from 0.0.0.0/0 to MySQL/MariaDB (Port 3306)",
    },
    5432: {
        "name": "PostgreSQL",
        "protocol": "tcp",
        "severity": Severity.HIGH,
        "compliance": ["PCI-DSS-4.0:1.3.1", "NIST-800-53:AC-17"],
        "check_id": "ec2_securitygroup_allow_ingress_db_ports",
        "check_title": "Ensure No Security Groups Allow Ingress from 0.0.0.0/0 to PostgreSQL (Port 5432)",
    },
    1433: {
        "name": "MSSQL",
        "protocol": "tcp",
        "severity": Severity.HIGH,
        "compliance": ["PCI-DSS-4.0:1.3.1", "NIST-800-53:AC-17"],
        "check_id": "ec2_securitygroup_allow_ingress_db_ports",
        "check_title": "Ensure No Security Groups Allow Ingress from 0.0.0.0/0 to Microsoft SQL Server (Port 1433)",
    },
    27017: {
        "name": "MongoDB",
        "protocol": "tcp",
        "severity": Severity.HIGH,
        "compliance": ["PCI-DSS-4.0:1.3.1", "NIST-800-53:AC-17"],
        "check_id": "ec2_securitygroup_allow_ingress_db_ports",
        "check_title": "Ensure No Security Groups Allow Ingress from 0.0.0.0/0 to MongoDB (Port 27017)",
    },
}

PUBLIC_CIDRS = {"0.0.0.0/0", "::/0"}


class ExposedSecurityGroupsCheck(BaseCheck):
    check_id = "ec2_securitygroup_allow_ingress_sensitive_ports"
    check_title = "Ensure Security Groups Do Not Allow Ingress from 0.0.0.0/0 or ::/0 to Sensitive Ports or All Traffic"
    service = "ec2"
    severity = Severity.CRITICAL
    compliance = [
        "CIS-AWS-1.4:5.2",
        "CIS-AWS-1.4:5.3",
        "NIST-800-53:AC-17",
        "PCI-DSS-4.0:1.3.1",
    ]

    def __init__(self, regions: Optional[List[str]] = None):
        self.regions = regions

    def _get_active_regions(self, session) -> List[str]:
        """Retrieve active/opted-in AWS regions across the account, using session cache if available."""
        cached_regions = getattr(session, "_cloudsentinel_active_regions", None)
        if isinstance(cached_regions, list) and cached_regions:
            return cached_regions

        session_region = getattr(session, "region_name", None) or "us-east-1"
        try:
            ec2 = session.client("ec2", region_name=session_region)
            resp = ec2.describe_regions(
                Filters=[{"Name": "opt-in-status", "Values": ["opt-in-not-required", "opted-in"]}]
            )
            regions = [r["RegionName"] for r in resp.get("Regions", []) if "RegionName" in r]
            result = sorted(regions) if regions else [session_region]
        except Exception:
            result = [session_region]

        try:
            session._cloudsentinel_active_regions = result
        except Exception:
            pass
        return result

    def run_check(self, session, group_ids: Optional[List[str]] = None, regions: Optional[List[str]] = None) -> List[Finding]:
        if group_ids:
            reg = getattr(session, "region_name", None) or "us-east-1"
            return self._audit_region(session, reg, group_ids=group_ids)

        target_regions = regions or getattr(self, "regions", None) or self._get_active_regions(session)
        if len(target_regions) <= 1:
            reg = target_regions[0] if target_regions else "us-east-1"
            return self._audit_region(session, reg)

        findings: List[Finding] = []
        # Pre-instantiate regional clients sequentially to ensure thread-safety with boto3.Session
        regional_clients = {r: session.client("ec2", region_name=r) for r in target_regions}
        with ThreadPoolExecutor(max_workers=min(8, len(target_regions))) as executor:
            for reg_findings in executor.map(lambda r: self._audit_region(session, r, ec2_client=regional_clients[r]), target_regions):
                findings.extend(reg_findings)
        return findings

    def _audit_region(self, session, region: str, group_ids: Optional[List[str]] = None, ec2_client=None) -> List[Finding]:
        ec2 = ec2_client or session.client("ec2", region_name=region)
        findings: List[Finding] = []

        try:
            security_groups = []
            if group_ids:
                resp = ec2.describe_security_groups(GroupIds=group_ids)
                security_groups.extend(resp.get("SecurityGroups", []))
            else:
                paginator = ec2.get_paginator("describe_security_groups")
                for page in paginator.paginate():
                    security_groups.extend(page.get("SecurityGroups", []))
        except botocore.exceptions.ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            if code in ("UnauthorizedOperation", "AccessDenied", "AccessDeniedException", "ForbiddenException"):
                return [
                    Finding(
                        check_id=self.check_id,
                        check_title=self.check_title,
                        service=self.service,
                        severity=self.severity,
                        status=Status.ACCESS_DENIED,
                        status_extended=f"Access Denied on ec2:DescribeSecurityGroups in region '{region}': {code} - {e.response.get('Error', {}).get('Message', str(e))}",
                        resource_id=f"arn:aws:ec2:{region}:::security-group/*",
                        resource_arn=f"arn:aws:ec2:{region}:::security-group/*",
                        region=region,
                        remediation=Remediation(
                            description="Insufficient IAM permissions to describe EC2 security groups.",
                            recommendation="Grant ec2:DescribeSecurityGroups or SecurityAudit policy to CloudSentinel IAM execution role.",
                            cli_command="aws iam attach-role-policy --role-name ScannerRole --policy-arn arn:aws:iam::aws:policy/SecurityAudit",
                            terraform_fix=(
                                "resource \"aws_iam_role_policy_attachment\" \"security_audit\" {\n"
                                "  role       = aws_iam_role.scanner.name\n"
                                "  policy_arn = \"arn:aws:iam::aws:policy/SecurityAudit\"\n"
                                "}"
                            ),
                            documentation_url="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/security-iam.html",
                        ),
                        compliance=self.compliance,
                    )
                ]
            raise

        for sg in security_groups:
            group_id = sg.get("GroupId", "unknown")
            group_name = sg.get("GroupName", "unknown")
            owner_id = sg.get("OwnerId", "")
            arn = sg.get("SecurityGroupArn") or f"arn:aws:ec2:{region}:{owner_id}:security-group/{group_id}"
            ip_permissions = sg.get("IpPermissions", [])

            violations = self._evaluate_permissions(ip_permissions)

            if violations:
                has_critical = any(v["severity"] == Severity.CRITICAL for v in violations)
                finding_severity = Severity.CRITICAL if has_critical else Severity.HIGH

                # Determine check_id and check_title based on detected violations
                ports_detected = {v["port"] for v in violations if v["port"] is not None}
                has_all_traffic = any(v["type"] == "ALL_TRAFFIC" for v in violations)

                if has_all_traffic and not ports_detected:
                    check_id = "ec2_securitygroup_allow_ingress_all_traffic"
                    check_title = "Ensure No Security Groups Allow Ingress from 0.0.0.0/0 or ::/0 to All Traffic"
                elif ports_detected == {22} and not has_all_traffic:
                    check_id = "ec2_securitygroup_allow_ingress_port_22"
                    check_title = "Ensure No Security Groups Allow Ingress from 0.0.0.0/0 to SSH (Port 22)"
                elif ports_detected == {3389} and not has_all_traffic:
                    check_id = "ec2_securitygroup_allow_ingress_port_3389"
                    check_title = "Ensure No Security Groups Allow Ingress from 0.0.0.0/0 to RDP (Port 3389)"
                elif ports_detected.issubset(set(DATABASE_PORTS.keys())) and not has_all_traffic:
                    check_id = "ec2_securitygroup_allow_ingress_db_ports"
                    check_title = "Ensure No Security Groups Allow Ingress from 0.0.0.0/0 to Database Ports"
                else:
                    check_id = self.check_id
                    check_title = self.check_title

                violation_summaries = []
                for v in violations:
                    if v["type"] == "ALL_TRAFFIC":
                        violation_summaries.append(f"ALL traffic/ports from {v['cidr']}")
                    else:
                        rule_from = v.get("rule_from_port")
                        rule_to = v.get("rule_to_port")
                        if rule_from is not None and rule_to is not None and rule_from != rule_to:
                            port_label = f"port range {rule_from}-{rule_to}"
                        elif rule_from is not None:
                            port_label = f"port {rule_from}"
                        else:
                            port_label = f"port {v['port']}"
                        violation_summaries.append(f"{v['name']} ({port_label}/{v['protocol']}) from {v['cidr']}")

                status_extended = (
                    f"Security group '{group_id}' ({group_name}) allows unrestricted public ingress: "
                    + ", ".join(violation_summaries)
                    + "."
                )

                cli_cmds = []
                seen_cmds = set()
                for v in violations:
                    if v["type"] == "ALL_TRAFFIC":
                        if v["cidr"] == "0.0.0.0/0":
                            cmd = f"aws ec2 revoke-security-group-ingress --group-id {group_id} --protocol all --cidr 0.0.0.0/0"
                        else:
                            cmd = (
                                f"aws ec2 revoke-security-group-ingress --group-id {group_id} --ip-permissions "
                                f"'[{{\"IpProtocol\": \"-1\", \"Ipv6Ranges\": [{{\"CidrIpv6\": \"{v['cidr']}\"}}]}}]'"
                            )
                    else:
                        proto = v["protocol"]
                        rule_from = v.get("rule_from_port")
                        rule_to = v.get("rule_to_port")
                        if rule_from is not None and rule_to is not None and rule_from != rule_to:
                            port_arg = f"{rule_from}-{rule_to}"
                            from_p, to_p = rule_from, rule_to
                        elif rule_from is not None and rule_to is not None:
                            port_arg = f"{rule_from}"
                            from_p, to_p = rule_from, rule_to
                        else:
                            port_arg = f"{v['port']}"
                            from_p, to_p = v["port"], v["port"]

                        if v["cidr"] == "0.0.0.0/0":
                            cmd = f"aws ec2 revoke-security-group-ingress --group-id {group_id} --protocol {proto} --port {port_arg} --cidr 0.0.0.0/0"
                        else:
                            cmd = (
                                f"aws ec2 revoke-security-group-ingress --group-id {group_id} --ip-permissions "
                                f"'[{{\"IpProtocol\": \"{proto}\", \"FromPort\": {from_p}, \"ToPort\": {to_p}, \"Ipv6Ranges\": [{{\"CidrIpv6\": \"{v['cidr']}\"}}]}}]'"
                            )

                    if cmd not in seen_cmds:
                        seen_cmds.add(cmd)
                        cli_cmds.append(cmd)

                first_rule_from = violations[0].get("rule_from_port")
                first_rule_to = violations[0].get("rule_to_port")
                if first_rule_from is not None and first_rule_to is not None:
                    first_from_port = first_rule_from
                    first_to_port = first_rule_to
                else:
                    first_from_port = violations[0]["port"] or 22
                    first_to_port = violations[0]["port"] or 22
                first_proto = violations[0]["protocol"] if violations[0]["protocol"] != "-1" else "tcp"

                terraform_fix = (
                    "# Option 1: Restrict ingress rule CIDR block to specific corporate IP / bastion\n"
                    "resource \"aws_security_group_rule\" \"restricted_ingress\" {\n"
                    "  type              = \"ingress\"\n"
                    f"  from_port         = {first_from_port}\n"
                    f"  to_port           = {first_to_port}\n"
                    f"  protocol          = \"{first_proto}\"\n"
                    "  cidr_blocks       = [\"198.51.100.14/32\"] # Restricted management IP\n"
                    f"  security_group_id = aws_security_group.app.id # {group_id}\n"
                    "}\n\n"
                    "# Option 2: Eliminate open inbound management rules and use AWS Systems Manager SSM Session Manager\n"
                    "# Reference: https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager.html"
                )

                compliance_tags = sorted(list(set(c for v in violations for c in v["compliance"])))

                findings.append(
                    Finding(
                        check_id=check_id,
                        check_title=check_title,
                        service=self.service,
                        severity=finding_severity,
                        status=Status.FAIL,
                        status_extended=status_extended,
                        resource_id=group_id,
                        resource_arn=arn,
                        region=region,
                        remediation=Remediation(
                            description=(
                                f"Security group '{group_id}' has public ingress open to the internet on sensitive "
                                "management or database ports, exposing services to brute-force attacks and remote exploits."
                            ),
                            recommendation="Remove 0.0.0.0/0 and ::/0 rules. Enforce restricted CIDRs or AWS Systems Manager Session Manager.",
                            cli_command="\n".join(cli_cmds),
                            terraform_fix=terraform_fix,
                            documentation_url="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/authorizing-access-to-an-instance.html",
                        ),
                        compliance=compliance_tags or self.compliance,
                    )
                )
            else:
                findings.append(
                    Finding(
                        check_id="ec2_securitygroup_safe_ingress",
                        check_title="Ensure Security Group Ingress Is Restricted",
                        service=self.service,
                        severity=Severity.CRITICAL,
                        status=Status.PASS,
                        status_extended=f"Security group '{group_id}' ({group_name}) has compliant ingress rules: no sensitive ports or all-traffic open to 0.0.0.0/0 or ::/0.",
                        resource_id=group_id,
                        resource_arn=arn,
                        region=region,
                        remediation=Remediation(
                            description="Security group is compliant with network boundary policies.",
                            recommendation="Maintain restricted CIDRs and private subnets.",
                            cli_command=f"# Compliant security group\naws ec2 describe-security-groups --group-ids {group_id}",
                            terraform_fix="# Ingress is properly restricted to private CIDRs or authorized web ports",
                        ),
                        compliance=["CIS-AWS-1.4:5.1", "CIS-AWS-1.4:5.2", "CIS-AWS-1.4:5.3"],
                    )
                )

        return findings

    def _evaluate_permissions(self, ip_permissions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Inspect ingress permissions and return detected violations.
        Safe rules (restricted CIDRs, web traffic 80/443 without sensitive ports, empty rules) produce no violations.
        """
        violations: List[Dict[str, Any]] = []

        for perm in ip_permissions:
            public_cidrs = []
            for ip_range in perm.get("IpRanges", []):
                cidr = ip_range.get("CidrIp")
                if cidr in PUBLIC_CIDRS:
                    public_cidrs.append(cidr)

            for ipv6_range in perm.get("Ipv6Ranges", []):
                cidr = ipv6_range.get("CidrIpv6")
                if cidr in PUBLIC_CIDRS:
                    public_cidrs.append(cidr)

            if not public_cidrs:
                continue

            protocol = str(perm.get("IpProtocol", "")).lower()
            from_port = perm.get("FromPort")
            to_port = perm.get("ToPort")

            # Case 1: All traffic / all ports (-1)
            if protocol == "-1":
                for cidr in public_cidrs:
                    violations.append({
                        "type": "ALL_TRAFFIC",
                        "port": None,
                        "rule_from_port": from_port,
                        "rule_to_port": to_port,
                        "name": "All Traffic",
                        "protocol": "-1",
                        "cidr": cidr,
                        "severity": Severity.CRITICAL,
                        "compliance": ["CIS-AWS-1.4:5.2", "CIS-AWS-1.4:5.3", "PCI-DSS-4.0:1.3.1"],
                    })
                continue

            # Case 2: Management ports (SSH 22, RDP 3389)
            for port, meta in SENSITIVE_MANAGEMENT_PORTS.items():
                if self._covers_port(protocol, from_port, to_port, port, is_rdp=(port == 3389)):
                    for cidr in public_cidrs:
                        violations.append({
                            "type": "PORT",
                            "port": port,
                            "rule_from_port": from_port,
                            "rule_to_port": to_port,
                            "name": meta["name"],
                            "protocol": protocol,
                            "cidr": cidr,
                            "severity": meta["severity"],
                            "compliance": meta["compliance"],
                        })

            # Case 3: Database ports (MySQL 3306, PostgreSQL 5432, MSSQL 1433, MongoDB 27017)
            for port, meta in DATABASE_PORTS.items():
                if self._covers_port(protocol, from_port, to_port, port, is_rdp=False):
                    for cidr in public_cidrs:
                        violations.append({
                            "type": "PORT",
                            "port": port,
                            "rule_from_port": from_port,
                            "rule_to_port": to_port,
                            "name": meta["name"],
                            "protocol": protocol,
                            "cidr": cidr,
                            "severity": meta["severity"],
                            "compliance": meta["compliance"],
                        })

        return violations

    @staticmethod
    def _covers_port(rule_proto: str, from_port: Optional[int], to_port: Optional[int], target_port: int, is_rdp: bool = False) -> bool:
        """Return True if rule protocol and port range covers the target port."""
        if is_rdp:
            allowed_protocols = ("tcp", "udp", "-1")
        else:
            allowed_protocols = ("tcp", "-1")

        if rule_proto not in allowed_protocols:
            return False

        if from_port is None and to_port is None:
            # Rule specifies protocol without port boundaries -> covers all ports
            return True

        if from_port is not None and to_port is not None:
            return from_port <= target_port <= to_port

        if from_port is not None:
            return from_port == target_port

        if to_port is not None:
            return target_port == to_port

        return False
