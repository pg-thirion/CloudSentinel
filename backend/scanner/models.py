"""
CloudSentinel Core Models
Defines status, severity, findings, and scan summary models matching Prowler standard.
"""
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import List, Dict, Any, Optional
import uuid
import datetime
import re


class CredentialProtector:
    """Ensures no AWS secret keys, session tokens, or sensitive values leak in logs or output."""
    PREFIX_PATTERNS = [
        re.compile(
            r'([\"\'\s]?(?:aws_)?(?:secret_?access_?key|session_?token)[\"\'\s]?\s*[:=]\s*[\"\']?)([^\s\"\'},]+)',
            re.IGNORECASE,
        ),
    ]
    KEY_PATTERNS = [
        re.compile(r'\b(AKIA[0-9A-Z]{16})\b', re.IGNORECASE),
        re.compile(r'\b(ASIA[0-9A-Z]{16})\b', re.IGNORECASE),
    ]

    @classmethod
    def redact(cls, text: str) -> str:
        if not text:
            return ""
        redacted = text
        for pattern in cls.PREFIX_PATTERNS:
            redacted = pattern.sub(r'\g<1>[REDACTED]', redacted)
        for pattern in cls.KEY_PATTERNS:
            redacted = pattern.sub(r'[REDACTED]', redacted)
        return redacted


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class Status(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    ACCESS_DENIED = "ACCESS_DENIED"
    ERROR = "ERROR"


@dataclass
class Remediation:
    description: str
    recommendation: str
    cli_command: str
    terraform_fix: str
    documentation_url: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Finding:
    check_id: str
    check_title: str
    service: str
    severity: Severity
    status: Status
    status_extended: str
    resource_id: str
    resource_arn: str
    region: str
    remediation: Remediation
    compliance: List[str] = field(default_factory=list)
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.value
        data["status"] = self.status.value
        return data


@dataclass
class ScanSummary:
    total_checks: int
    passed_checks: int
    failed_checks: int
    access_denied_checks: int
    error_checks: int
    security_score: float
    score_band: str
    is_complete: bool
    completeness_percentage: float
    severity_breakdown: Dict[str, int]
    service_breakdown: Dict[str, Dict[str, Any]]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
