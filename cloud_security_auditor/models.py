"""Shared typed data models for scanner and reporter output."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


@dataclass(frozen=True)
class Finding:
    finding_id: str
    rule_id: str
    source: str
    resource: str
    title: str
    severity: Severity
    description: str
    remediation: str
    cis_controls: tuple[str, ...] = ()
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["severity"] = self.severity.value
        result["cis_controls"] = list(self.cis_controls)
        return result


@dataclass
class AuditResult:
    platform: str
    findings: list[Finding] = field(default_factory=list)
    resources_scanned: int = 0
    errors: list[str] = field(default_factory=list)
    generated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "platform": self.platform,
            "generated_at": self.generated_at,
            "resources_scanned": self.resources_scanned,
            "summary": {
                "findings": len(self.findings),
                "by_severity": {
                    severity.value: sum(
                        finding.severity == severity for finding in self.findings
                    )
                    for severity in Severity
                },
            },
            "compliance": self.compliance_summary(),
            "errors": self.errors,
            "findings": [finding.to_dict() for finding in self.findings],
        }

    def compliance_summary(self) -> dict[str, Any]:
        from cloud_security_auditor.cis.engine import compliance_summary

        return compliance_summary(self)

