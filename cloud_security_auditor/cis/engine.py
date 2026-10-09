"""Calculate control-level compliance for the rules evaluated by this auditor."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from cloud_security_auditor.cis.mappings import CONTROLS

if TYPE_CHECKING:
    from cloud_security_auditor.models import AuditResult


PLATFORM_RULES: dict[str, tuple[str, ...]] = {
    "aws": (
        "aws.s3.public_access",
        "aws.iam.root_usage",
        "aws.iam.wildcard_admin",
        "aws.ec2.open_admin_port",
        "aws.ebs.unencrypted",
    ),
    "k8s": (
        "k8s.container.privileged",
        "k8s.container.root",
        "k8s.container.net_raw_capability",
        "k8s.container.resource_limits",
        "k8s.volume.sensitive_hostpath",
        "k8s.container.dangerous_capability",
    ),
}


def compliance_summary(result: AuditResult) -> dict[str, Any]:
    rules = PLATFORM_RULES.get(result.platform, ())
    in_scope = [rule for rule in rules if rule in CONTROLS]
    failed = {finding.rule_id for finding in result.findings}
    failed_controls = [rule for rule in in_scope if rule in failed]
    total = len(in_scope)
    passed = total - len(failed_controls)
    return {
        "benchmark": (
            "CIS AWS Foundations Benchmark v1.5.0"
            if result.platform == "aws"
            else "CIS Kubernetes Benchmark v1.8.0"
            if result.platform == "k8s"
            else "CIS benchmark mappings"
        ),
        "controls_evaluated": total,
        "controls_passed": passed,
        "controls_failed": len(failed_controls),
        "percentage": (
            round((passed / total) * 100, 1)
            if total and not result.errors
            else None
        ),
        "scope_note": (
            "Percentage covers only controls mapped to checks implemented by this auditor; "
            "it is not a full benchmark certification."
        ),
    }
