"""
CloudSentinel Base Check Interface
Defines standard contract for all security checks with automatic ClientError / AccessDenied handling.
"""
from abc import ABC, abstractmethod
from typing import List
import botocore.exceptions
from ..models import Finding, Severity, Status, Remediation


class BaseCheck(ABC):
    check_id: str
    check_title: str
    service: str
    severity: Severity
    compliance: List[str]

    @staticmethod
    def _redact(text: str) -> str:
        """Sanitize error messages to prevent AWS credential leakage."""
        try:
            from ..engine import CredentialProtector
            return CredentialProtector.redact(text)
        except Exception:
            return text

    @abstractmethod
    def run_check(self, session, **kwargs) -> List[Finding]:
        """Implement check logic using boto3 session. Must raise or handle appropriately."""
        pass

    def execute(self, session, **kwargs) -> List[Finding]:
        """Wrapper ensuring AccessDenied and errors are captured cleanly without crashing."""
        try:
            return self.run_check(session, **kwargs)
        except botocore.exceptions.ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "ClientError")
            raw_message = e.response.get("Error", {}).get("Message", str(e))
            error_message = self._redact(raw_message)
            region = getattr(session, "region_name", "global") or "global"
            
            if error_code in ("AccessDenied", "AccessDeniedException", "UnauthorizedOperation", "ForbiddenException"):
                return [
                    Finding(
                        check_id=self.check_id,
                        check_title=self.check_title,
                        service=self.service,
                        severity=self.severity,
                        status=Status.ACCESS_DENIED,
                        status_extended=f"Access Denied executing check: {error_code} - {error_message}",
                        resource_id=f"arn:aws:{self.service}:::*",
                        resource_arn=f"arn:aws:{self.service}:::*",
                        region=region,
                        remediation=Remediation(
                            description=f"Insufficient IAM permissions to audit {self.service}.",
                            recommendation="Grant read-only permissions to CloudSentinel IAM execution role.",
                            cli_command=f"aws iam attach-role-policy --role-name <ScannerRole> --policy-arn arn:aws:iam::aws:policy/SecurityAudit",
                            terraform_fix="# Add SecurityAudit or minimal read policy to CloudSentinel role\nresource \"aws_iam_role_policy_attachment\" \"audit\" {\n  role       = aws_iam_role.scanner.name\n  policy_arn = \"arn:aws:iam::aws:policy/SecurityAudit\"\n}",
                        ),
                        compliance=self.compliance,
                    )
                ]
            else:
                return [
                    Finding(
                        check_id=self.check_id,
                        check_title=self.check_title,
                        service=self.service,
                        severity=self.severity,
                        status=Status.ERROR,
                        status_extended=f"Error executing check: {error_code} - {error_message}",
                        resource_id=f"arn:aws:{self.service}:::*",
                        resource_arn=f"arn:aws:{self.service}:::*",
                        region=region,
                        remediation=Remediation(
                            description="API error during evaluation.",
                            recommendation="Verify AWS service availability and credentials.",
                            cli_command="# Check AWS STS status\naws sts get-caller-identity",
                            terraform_fix="",
                        ),
                        compliance=self.compliance,
                    )
                ]
        except Exception as e:
            redacted_exc = self._redact(str(e))
            return [
                Finding(
                    check_id=self.check_id,
                    check_title=self.check_title,
                    service=self.service,
                    severity=self.severity,
                    status=Status.ERROR,
                    status_extended=f"Unexpected scanner exception: {redacted_exc}",
                    resource_id=f"arn:aws:{self.service}:::*",
                    resource_arn=f"arn:aws:{self.service}:::*",
                    region="global",
                    remediation=Remediation(
                        description="Internal scanner error.",
                        recommendation="Review execution logs.",
                        cli_command="",
                        terraform_fix="",
                    ),
                    compliance=self.compliance,
                )
            ]
