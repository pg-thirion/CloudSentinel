"""
CloudSentinel IAM Risky Policies Detection Engine
Identifies customer managed IAM policies that grant full administrative wildcards (*:*)
or known AWS IAM privilege escalation vectors according to CIS AWS Foundations Benchmark,
NIST SP 800-53, and Prowler security standards.
"""
import fnmatch
import json
import urllib.parse
from typing import List, Dict, Any, Optional, Tuple, Set
import botocore.exceptions

from ..models import Finding, Severity, Status, Remediation
from .base import BaseCheck


# Known AWS IAM Privilege Escalation Vectors
PRIVESC_RULES = [
    {
        "id": "iam:CreatePolicyVersion",
        "name": "IAM Policy Version Creation",
        "description": "Allows creating a new policy version with full administrator privileges and setting it as default.",
        "type": "single",
        "actions": ["iam:createpolicyversion"],
    },
    {
        "id": "iam:SetDefaultPolicyVersion",
        "name": "IAM Default Policy Version Switching",
        "description": "Allows switching the active default version of a policy to an older version with administrative privileges.",
        "type": "single",
        "actions": ["iam:setdefaultpolicyversion"],
    },
    {
        "id": "iam:PassRole_EC2",
        "name": "IAM PassRole to EC2",
        "description": "Allows passing an administrative IAM role to a newly launched EC2 instance, enabling full credential extraction via IMDS.",
        "type": "combo",
        "required_action_groups": [
            ["iam:passrole"],
            ["ec2:runinstances", "ec2:*", "*"]
        ],
    },
    {
        "id": "iam:PassRole_Lambda",
        "name": "IAM PassRole to Lambda",
        "description": "Allows passing an administrative IAM role to a Lambda function to execute arbitrary code with elevated permissions.",
        "type": "combo",
        "required_action_groups": [
            ["iam:passrole"],
            ["lambda:createfunction", "lambda:createeventsourcemapping", "lambda:*", "*"]
        ],
    },
    {
        "id": "iam:AttachPolicy",
        "name": "IAM Policy Attachment",
        "description": "Allows attaching arbitrary managed policies (including AdministratorAccess) directly to users, groups, or roles.",
        "type": "any",
        "actions": [
            "iam:attachuserpolicy",
            "iam:attachgrouppolicy",
            "iam:attachrolepolicy",
        ],
    },
    {
        "id": "iam:PutPolicy",
        "name": "IAM Inline Policy Injection",
        "description": "Allows creating or updating inline administrative policies on users, groups, or roles.",
        "type": "any",
        "actions": [
            "iam:putuserpolicy",
            "iam:putgrouppolicy",
            "iam:putrolepolicy",
        ],
    },
    {
        "id": "iam:UpdateAssumeRolePolicy",
        "name": "IAM Role Trust Modification",
        "description": "Allows modifying the trust relationship of an IAM role to allow unauthorized identities to assume it.",
        "type": "single",
        "actions": ["iam:updateassumerolepolicy"],
    },
    {
        "id": "iam:CreateAccessKey",
        "name": "IAM Access Key Generation",
        "description": "Allows generating access key pairs for any IAM user, including administrators.",
        "type": "single",
        "actions": ["iam:createaccesskey"],
    },
    {
        "id": "iam:LoginProfilePrivesc",
        "name": "IAM Console Login Profile Hijack",
        "description": "Allows creating or updating console login passwords for other IAM users.",
        "type": "any",
        "actions": [
            "iam:createloginprofile",
            "iam:updateloginprofile",
        ],
    },
    {
        "id": "iam:AddUserToGroup",
        "name": "IAM Group Membership Escalation",
        "description": "Allows adding identities to high-privilege IAM groups (e.g., Admins).",
        "type": "single",
        "actions": ["iam:addusertogroup"],
    },
]


class IAMRiskyPoliciesCheck(BaseCheck):
    """
    Scans customer-managed IAM policies to detect:
    1. Unrestricted full administrator wildcards (*:*).
    2. Known AWS IAM privilege escalation vectors.
    """
    check_id = "iam_risky_policies"
    check_title = "Ensure IAM Policies Do Not Grant Full Admin Or Privilege Escalation"
    service = "iam"
    severity = Severity.CRITICAL
    compliance = [
        "CIS-AWS-1.4:1.16",
        "CIS-AWS-1.4:1.22",
        "NIST-800-53:AC-2",
        "NIST-800-53:AC-6",
        "PCI-DSS-v3.2.1:7.1.2",
    ]

    def _fetch_policies_and_documents(self, iam) -> List[Dict[str, Any]]:
        """
        Attempts fast single-call batch retrieval using get_account_authorization_details.
        Prevents N+1 API calls and rate-limiting ThrottlingException on accounts with many policies.
        Falls back seamlessly to list_policies if get_account_authorization_details is unauthorized or unmocked.
        """
        try:
            paginator = iam.get_paginator("get_account_authorization_details")
            policies = []
            for page in paginator.paginate(Filter=["LocalManagedPolicy"]):
                for pol_detail in page.get("Policies", []):
                    # Only treat as batch authorization details if PolicyVersionList is explicitly returned
                    if "PolicyVersionList" not in pol_detail:
                        continue
                    arn = pol_detail.get("Arn")
                    doc = {}
                    default_ver = pol_detail.get("DefaultVersionId", "v1")
                    for v in pol_detail.get("PolicyVersionList", []):
                        if v.get("IsDefaultVersion"):
                            default_ver = v.get("VersionId", default_ver)
                            doc = v.get("Document", {})
                            break
                    policies.append({
                        "Arn": arn,
                        "PolicyName": pol_detail.get("PolicyName", arn.split("/")[-1]),
                        "DefaultVersionId": default_ver,
                        "PolicyDocument": doc,
                    })
            if policies:
                return policies
        except Exception:
            pass

        return self._list_local_policies(iam)

    def run_check(self, session) -> List[Finding]:
        """
        Execute scan across all customer managed policies in the AWS account.
        Catches botocore ClientError exceptions for AccessDenied at both list and get operations.
        """
        iam = session.client("iam")
        findings: List[Finding] = []

        # 1. Fetch customer managed policies (batch-optimized to prevent N+1 API rate limits)
        try:
            policies = self._fetch_policies_and_documents(iam)
        except botocore.exceptions.ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "ClientError")
            error_msg = e.response.get("Error", {}).get("Message", str(e))
            if error_code in ("AccessDenied", "AccessDeniedException", "UnauthorizedOperation", "ForbiddenException"):
                return [self._build_access_denied_finding("arn:aws:iam:::policy/*", error_code, error_msg)]
            raise

        if not policies:
            return [
                Finding(
                    check_id="iam_policy_least_privilege",
                    check_title="Ensure IAM Policies Follow Least Privilege",
                    service=self.service,
                    severity=self.severity,
                    status=Status.PASS,
                    status_extended="No customer managed IAM policies found in this AWS account.",
                    resource_id="no-customer-policies",
                    resource_arn="arn:aws:iam:::policy/none",
                    region="global",
                    remediation=self._build_compliant_remediation("No customer managed policies"),
                    compliance=self.compliance,
                )
            ]

        # 2. Inspect each policy document
        for policy in policies:
            policy_arn = policy["Arn"]
            policy_name = policy.get("PolicyName", policy_arn.split("/")[-1])
            default_version_id = policy.get("DefaultVersionId", "v1")

            try:
                document = self._get_policy_document(iam, policy, policy_arn, default_version_id)
            except botocore.exceptions.ClientError as e:
                error_code = e.response.get("Error", {}).get("Code", "ClientError")
                error_msg = e.response.get("Error", {}).get("Message", str(e))
                if error_code in ("AccessDenied", "AccessDeniedException", "UnauthorizedOperation", "ForbiddenException"):
                    findings.append(self._build_access_denied_finding(policy_arn, error_code, error_msg, policy_name=policy_name))
                    continue
                raise

            # 3. Evaluate policy document
            finding = self.evaluate_policy(
                policy_name=policy_name,
                policy_arn=policy_arn,
                document=document,
                default_version_id=default_version_id,
            )
            findings.append(finding)

        return findings

    def evaluate_policy(
        self,
        policy_name: str,
        policy_arn: str,
        document: Any,
        default_version_id: str = "v1",
    ) -> Finding:
        """
        Evaluates an individual IAM policy document for:
        - Full Administrator wildcards (*:*)
        - Privilege escalation vectors
        Returns a Finding with status FAIL or PASS and comprehensive remediation.
        """
        parsed_doc = self._parse_document(document)
        statements = self._extract_statements(parsed_doc)

        # Check 1: Admin Wildcards
        is_admin_wildcard, admin_reasons = self._check_admin_wildcards(statements)

        # Check 2: Privilege Escalation Vectors
        privesc_vectors, privesc_descriptions = self._check_privilege_escalation(statements)

        # Evaluate risk posture
        if is_admin_wildcard:
            reason_text = " ".join(admin_reasons)
            if privesc_vectors:
                reason_text += f" Policy also allows privilege escalation vectors: {', '.join(privesc_vectors)}."

            return Finding(
                check_id="iam_policy_wildcard_administrative_access",
                check_title="Ensure No IAM Policy Grants Full Administrative Wildcard (*:*)",
                service=self.service,
                severity=Severity.CRITICAL,
                status=Status.FAIL,
                status_extended=f"Policy '{policy_name}' grants full administrative wildcard (*:*). {reason_text}",
                resource_id=policy_name,
                resource_arn=policy_arn,
                region="global",
                remediation=self._build_admin_wildcard_remediation(policy_name, policy_arn),
                compliance=["CIS-AWS-1.4:1.22", "NIST-800-53:AC-2", "PCI-DSS-v3.2.1:7.1.2"],
            )

        if privesc_vectors:
            vector_summary = "; ".join(privesc_descriptions)
            return Finding(
                check_id="iam_policy_allows_privilege_escalation",
                check_title="Ensure IAM Policies Do Not Allow Privilege Escalation",
                service=self.service,
                severity=Severity.CRITICAL,
                status=Status.FAIL,
                status_extended=(
                    f"Policy '{policy_name}' enables privilege escalation vectors: {', '.join(privesc_vectors)}. "
                    f"Details: {vector_summary}"
                ),
                resource_id=policy_name,
                resource_arn=policy_arn,
                region="global",
                remediation=self._build_privesc_remediation(policy_name, policy_arn, privesc_vectors, default_version_id),
                compliance=["CIS-AWS-1.4:1.16", "NIST-800-53:AC-6"],
            )

        # Policy is safe / hardened
        return Finding(
            check_id="iam_policy_least_privilege",
            check_title="Ensure IAM Policies Follow Least Privilege",
            service=self.service,
            severity=Severity.CRITICAL,
            status=Status.PASS,
            status_extended=(
                f"Policy '{policy_name}' adheres to least-privilege standards: "
                "no unrestricted administrative wildcards or privilege escalation vectors detected."
            ),
            resource_id=policy_name,
            resource_arn=policy_arn,
            region="global",
            remediation=self._build_compliant_remediation(policy_name, policy_arn),
            compliance=self.compliance,
        )

    # -------------------------------------------------------------------------
    # Helper Inspection Methods
    # -------------------------------------------------------------------------

    def _list_local_policies(self, iam) -> List[Dict[str, Any]]:
        """Retrieve local customer managed policies with fallback for mocks/stubs."""
        try:
            paginator = iam.get_paginator("list_policies")
            policies = []
            for page in paginator.paginate(Scope="Local"):
                policies.extend(page.get("Policies", []))
            return policies
        except (AttributeError, botocore.exceptions.OperationNotPageableError):
            resp = iam.list_policies(Scope="Local")
            return resp.get("Policies", [])

    def _get_policy_document(self, iam, policy: Dict[str, Any], policy_arn: str, default_version_id: str) -> Any:
        """Retrieve policy document from policy dict or via get_policy_version."""
        if "PolicyDocument" in policy:
            return policy["PolicyDocument"]
        if "Document" in policy:
            return policy["Document"]

        resp = iam.get_policy_version(
            PolicyArn=policy_arn,
            VersionId=default_version_id,
        )
        return resp.get("PolicyVersion", {}).get("Document", {})

    def _parse_document(self, raw_document: Any) -> Dict[str, Any]:
        """Normalize policy document from string, URL-encoded string, or dict."""
        if isinstance(raw_document, dict):
            return raw_document
        if isinstance(raw_document, str):
            try:
                return json.loads(raw_document)
            except Exception:
                try:
                    unquoted = urllib.parse.unquote(raw_document)
                    return json.loads(unquoted)
                except Exception:
                    return {}
        return {}

    def _extract_statements(self, doc: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract statements list from document."""
        stmts = doc.get("Statement", [])
        if isinstance(stmts, dict):
            return [stmts]
        if isinstance(stmts, list):
            return stmts
        return []

    def _check_admin_wildcards(self, statements: List[Dict[str, Any]]) -> Tuple[bool, List[str]]:
        """
        Detects statements with Effect: Allow, Action: '*' (or contains '*'),
        Resource: '*' (or contains '*') without restrictive conditions.
        """
        reasons = []
        is_admin = False

        for idx, stmt in enumerate(statements):
            if stmt.get("Effect") != "Allow":
                continue

            actions = stmt.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]

            resources = stmt.get("Resource", [])
            if isinstance(resources, str):
                resources = [resources]

            not_actions = stmt.get("NotAction", [])
            if isinstance(not_actions, str):
                not_actions = [not_actions]

            has_wildcard_action = (
                "*" in actions
                or "*:*" in actions
                or any(a.strip() in ("*", "*:*") for a in actions)
            )

            has_wildcard_resource = (
                "*" in resources
                or any(r.strip() == "*" for r in resources)
            )

            condition = stmt.get("Condition")
            has_restrictive_condition = self._is_restrictive_condition(condition)

            # Standard full admin wildcard
            if has_wildcard_action and has_wildcard_resource and not has_restrictive_condition:
                is_admin = True
                reasons.append(
                    f"Statement {idx + 1} allows full administrative wildcard ('*') on all resources ('*') "
                    "without restrictive conditions."
                )

            # NotAction with Resource: * is also full account administrative access
            if not_actions and has_wildcard_resource and not has_restrictive_condition:
                is_admin = True
                reasons.append(
                    f"Statement {idx + 1} uses 'NotAction' with wildcard resource ('*'), granting all unrestricted actions "
                    "except excluded list."
                )

        return is_admin, reasons

    def _check_privilege_escalation(self, statements: List[Dict[str, Any]]) -> Tuple[List[str], List[str]]:
        """
        Detects known AWS IAM privilege escalation vectors across all Allow statements.
        Supports single action vectors and multi-action combos (e.g. iam:PassRole + ec2:RunInstances).
        """
        # Collect all allowed actions across all Effect: Allow statements
        all_allowed_actions: List[str] = []
        statement_allowed_actions: List[List[str]] = []

        for stmt in statements:
            if stmt.get("Effect") != "Allow":
                continue
            actions = stmt.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]
            actions_clean = [a.strip() for a in actions if isinstance(a, str)]
            all_allowed_actions.extend(actions_clean)
            statement_allowed_actions.append(actions_clean)

        detected_vectors: List[str] = []
        descriptions: List[str] = []

        # Check if policy has at least one statement granting unrestricted iam:PassRole
        policy_has_unrestricted_pass_role = any(
            self._statement_has_unrestricted_pass_role(stmt)
            for stmt in statements
        )

        for rule in PRIVESC_RULES:
            rule_id = rule["id"]
            rule_name = rule["name"]
            rule_desc = rule["description"]
            rule_type = rule["type"]

            is_triggered = False

            if rule_type in ("single", "any"):
                target_actions = rule["actions"]
                for target in target_actions:
                    if self._actions_allow_target(all_allowed_actions, target):
                        is_triggered = True
                        break

            elif rule_type == "combo":
                # For PassRole combo rules, only flag if iam:PassRole is unrestricted
                # (Resource contains wildcard AND lacks restrictive condition like iam:PassedToService)
                involves_pass_role = any(
                    "iam:passrole" in [t.lower() for t in group]
                    for group in rule["required_action_groups"]
                )
                if involves_pass_role and not policy_has_unrestricted_pass_role:
                    continue

                # All required action groups must be satisfied
                required_groups = rule["required_action_groups"]
                groups_satisfied = 0
                for group in required_groups:
                    group_hit = any(
                        self._actions_allow_target(all_allowed_actions, target)
                        for target in group
                    )
                    if group_hit:
                        groups_satisfied += 1

                if groups_satisfied == len(required_groups):
                    is_triggered = True

            if is_triggered:
                detected_vectors.append(rule_id)
                descriptions.append(f"{rule_name} ({rule_desc})")

        return detected_vectors, descriptions

    def _statement_has_unrestricted_pass_role(self, stmt: Dict[str, Any]) -> bool:
        """
        Evaluates whether an Allow statement granting iam:PassRole is unrestricted.
        Per least-privilege standards:
        iam:PassRole is only flagged as privilege escalation if Resource contains a wildcard ('*')
        AND lacks a restrictive condition such as 'iam:PassedToService'.
        """
        if stmt.get("Effect") != "Allow":
            return False

        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]

        allows_pass_role = any(
            self._action_matches_target(a, "iam:passrole")
            for a in actions if isinstance(a, str)
        )
        if not allows_pass_role:
            return False

        resources = stmt.get("Resource", [])
        if isinstance(resources, str):
            resources = [resources]

        has_wildcard_resource = any("*" in str(r) for r in resources)

        # Check for restrictive condition like iam:PassedToService
        condition = stmt.get("Condition", {})
        has_passed_to_service = False
        if isinstance(condition, dict):
            for operator, op_dict in condition.items():
                if isinstance(op_dict, dict):
                    for cond_key in op_dict.keys():
                        if cond_key.strip().lower() == "iam:passedtoservice":
                            has_passed_to_service = True
                            break

        return has_wildcard_resource and not has_passed_to_service

    def _action_matches_target(self, action_pattern: str, target_action: str) -> bool:
        """Case-insensitive pattern matcher for individual IAM action."""
        act = action_pattern.strip().lower()
        tgt = target_action.strip().lower()
        if act in ("*", "*:*"):
            return True
        return fnmatch.fnmatch(tgt, act)

    def _actions_allow_target(self, allowed_actions: List[str], target_action: str) -> bool:
        """
        Checks whether any allowed action pattern grants the target action.
        Case-insensitive with fnmatch wildcard expansion.
        """
        target = target_action.strip().lower()
        for allowed in allowed_actions:
            act = allowed.strip().lower()
            if act in ("*", "*:*"):
                return True
            if fnmatch.fnmatch(target, act):
                return True
        return False

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
        "aws:multifactorauthpresent",
        "aws:requestedregion",
    }

    def _is_restrictive_condition(self, condition: Any) -> bool:
        """
        Checks if condition dictionary contains restrictive constraints
        (e.g. aws:SourceIp, aws:PrincipalArn, aws:MultiFactorAuthPresent, etc.).
        """
        if not condition or not isinstance(condition, dict) or len(condition) == 0:
            return False

        for op, keys in condition.items():
            if isinstance(keys, dict):
                for key in keys.keys():
                    key_lower = key.lower().strip()
                    if key_lower in self.RESTRICTIVE_CONDITION_KEYS:
                        return True
                    if any(r_key in key_lower for r_key in self.RESTRICTIVE_CONDITION_KEYS):
                        return True
        return False

    # -------------------------------------------------------------------------
    # Remediation Builders
    # -------------------------------------------------------------------------

    def _build_admin_wildcard_remediation(self, policy_name: str, policy_arn: str) -> Remediation:
        return Remediation(
            description=(
                f"Policy '{policy_name}' allows unrestricted administrative access ('*:*') across all AWS resources "
                "without restrictive condition boundaries. Principals with this policy have full control over the account, "
                "enabling unauthorized infrastructure creation, deletion, or credential manipulation."
            ),
            recommendation=(
                "Replace full administrative wildcards with granular role-based policies tailored to specific job functions. "
                "Use AWS IAM Access Analyzer or CloudTrail event logs to generate a least-privilege policy document."
            ),
            cli_command=(
                f"# Step 1: Identify all entities attached to the administrative policy\n"
                f"aws iam list-entities-for-policy --policy-arn {policy_arn}\n\n"
                f"# Step 2: Detach policy from attached roles, users, or groups\n"
                f"aws iam detach-role-policy --role-name <RoleName> --policy-arn {policy_arn}\n"
                f"aws iam detach-user-policy --user-name <UserName> --policy-arn {policy_arn}\n"
                f"aws iam detach-group-policy --group-name <GroupName> --policy-arn {policy_arn}\n\n"
                f"# Step 3: Delete the insecure wildcard policy\n"
                f"aws iam delete-policy --policy-arn {policy_arn}"
            ),
            terraform_fix=(
                "# Replace full wildcard (*:*) with granular, resource-scoped permissions\n"
                "data \"aws_iam_policy_document\" \"least_privilege\" {\n"
                "  statement {\n"
                "    sid       = \"ScopedServiceAccess\"\n"
                "    effect    = \"Allow\"\n"
                "    actions   = [\n"
                "      \"s3:GetObject\",\n"
                "      \"s3:ListBucket\",\n"
                "      \"ec2:DescribeInstances\"\n"
                "    ]\n"
                "    resources = [\n"
                "      \"arn:aws:s3:::production-app-bucket\",\n"
                "      \"arn:aws:s3:::production-app-bucket/*\"\n"
                "    ]\n"
                "  }\n"
                "}"
            ),
            documentation_url="https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege",
        )

    def _build_privesc_remediation(
        self,
        policy_name: str,
        policy_arn: str,
        vectors: List[str],
        default_version_id: str,
    ) -> Remediation:
        vector_str = ", ".join(vectors)
        return Remediation(
            description=(
                f"Policy '{policy_name}' contains permissions known to facilitate AWS privilege escalation ({vector_str}). "
                "Attackers or compromised identities possessing these permissions can elevate themselves to full AdministratorAccess "
                "by passing roles to compute resources, creating new default policy versions, or injecting inline policies."
            ),
            recommendation=(
                "Scope down sensitive IAM actions: restrict iam:PassRole to specific role ARNs and enforce the "
                "'iam:PassedToService' condition key. Remove iam:CreatePolicyVersion, iam:Attach*Policy, and iam:Put*Policy "
                "from non-administrative roles."
            ),
            cli_command=(
                f"# Step 1: Create a scoped least-privilege policy version without privesc vectors\n"
                f"aws iam create-policy-version \\\n"
                f"  --policy-arn {policy_arn} \\\n"
                f"  --policy-document file://scoped_least_privilege.json \\\n"
                f"  --set-as-default\n\n"
                f"# Step 2: Delete the vulnerable policy version ({default_version_id})\n"
                f"aws iam delete-policy-version \\\n"
                f"  --policy-arn {policy_arn} \\\n"
                f"  --version-id {default_version_id}"
            ),
            terraform_fix=(
                "# Safe PassRole implementation scoped to specific role and service destination\n"
                "statement {\n"
                "  sid       = \"ScopedPassRoleToEC2\"\n"
                "  effect    = \"Allow\"\n"
                "  actions   = [\"iam:PassRole\"]\n"
                "  resources = [\"arn:aws:iam::123456789012:role/SpecificAppExecutionRole\"]\n"
                "  condition {\n"
                "    test     = \"StringEquals\"\n"
                "    variable = \"iam:PassedToService\"\n"
                "    values   = [\"ec2.amazonaws.com\"]\n"
                "  }\n"
                "}"
            ),
            documentation_url="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_passrole.html",
        )

    def _build_compliant_remediation(self, policy_name: str, policy_arn: Optional[str] = None) -> Remediation:
        arn_ref = policy_arn or "<PolicyArn>"
        return Remediation(
            description=f"Policy '{policy_name}' adheres to least-privilege standards without wildcard admin or privilege escalation vectors.",
            recommendation="Maintain current policy scoping and conduct periodic access reviews using AWS IAM Access Analyzer.",
            cli_command=f"# Policy is compliant. Review attached identities:\naws iam list-entities-for-policy --policy-arn {arn_ref}",
            terraform_fix="# Compliant least-privilege policy structure maintained.",
            documentation_url="https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html",
        )

    def _build_access_denied_finding(
        self,
        resource_arn: str,
        error_code: str,
        error_message: str,
        policy_name: Optional[str] = None,
    ) -> Finding:
        res_id = policy_name or resource_arn.split("/")[-1]
        return Finding(
            check_id=self.check_id,
            check_title=self.check_title,
            service=self.service,
            severity=self.severity,
            status=Status.ACCESS_DENIED,
            status_extended=f"Access Denied auditing IAM policies: {error_code} - {error_message}",
            resource_id=res_id,
            resource_arn=resource_arn,
            region="global",
            remediation=Remediation(
                description="CloudSentinel scanner role lacks IAM permissions to inspect customer managed policies.",
                recommendation="Attach the AWS managed 'SecurityAudit' policy to provide read-only security posture visibility.",
                cli_command="aws iam attach-role-policy --role-name <CloudSentinelScannerRole> --policy-arn arn:aws:iam::aws:policy/SecurityAudit",
                terraform_fix=(
                    "resource \"aws_iam_role_policy_attachment\" \"scanner_security_audit\" {\n"
                    "  role       = aws_iam_role.cloudsentinel_scanner.name\n"
                    "  policy_arn = \"arn:aws:iam::aws:policy/SecurityAudit\"\n"
                    "}"
                ),
                documentation_url="https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed-vs-inline.html",
            ),
            compliance=self.compliance,
        )
