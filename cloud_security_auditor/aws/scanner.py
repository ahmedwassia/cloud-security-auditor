"""AWS posture checks with both live boto3 and deterministic fixture inputs."""

from __future__ import annotations

import hashlib
import json
import time
from datetime import datetime, timedelta, timezone
from importlib.resources import files
from typing import Any

from cloud_security_auditor.cis.mappings import controls_for_rule
from cloud_security_auditor.models import AuditResult, Finding, Severity


def _finding(
    rule_id: str,
    resource: str,
    title: str,
    severity: Severity,
    description: str,
    remediation: str,
    evidence: dict[str, Any] | None = None,
) -> Finding:
    identity = json.dumps(
        {"resource": resource, "title": title, "evidence": evidence or {}},
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return Finding(
        finding_id=f"{rule_id}:{hashlib.sha256(identity.encode()).hexdigest()[:16]}",
        rule_id=rule_id,
        source="aws",
        resource=resource,
        title=title,
        severity=severity,
        description=description,
        remediation=remediation,
        cis_controls=controls_for_rule(rule_id),
        evidence=evidence or {},
    )


def load_mock_data() -> dict[str, Any]:
    """Load the shipped service-shaped AWS demo responses."""
    return json.loads(
        files("cloud_security_auditor.aws")
        .joinpath("mock_data.json")
        .read_text(encoding="utf-8")
    )


def _is_wildcard_admin(document: dict[str, Any]) -> bool:
    statements = document.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    for statement in statements:
        if not isinstance(statement, dict) or statement.get("Effect") != "Allow":
            continue
        actions = statement.get("Action", [])
        resources = statement.get("Resource", [])
        if isinstance(actions, str):
            actions = [actions]
        if isinstance(resources, str):
            resources = [resources]
        if any(action == "*" or action.endswith(":*") for action in actions) and "*" in resources:
            return True
    return False


def _statements(policy: dict[str, Any]) -> list[dict[str, Any]]:
    statements = policy.get("Statement", [])
    if isinstance(statements, dict):
        return [statements]
    return [statement for statement in statements if isinstance(statement, dict)]


def _has_public_policy(policy: dict[str, Any]) -> bool:
    return any(
        statement.get("Effect") == "Allow"
        and (
            statement.get("Principal") == "*"
            or (
                isinstance(statement.get("Principal"), dict)
                and statement["Principal"].get("AWS") == "*"
            )
        )
        for statement in _statements(policy)
    )


def _is_true(value: Any) -> bool:
    return str(value).lower() == "true"


def scan_aws_data(data: dict[str, Any]) -> AuditResult:
    """Evaluate normalized, service-shaped AWS responses (also used by tests)."""
    result = AuditResult(platform="aws")
    buckets = data.get("buckets", [])
    groups = data.get("security_groups", [])
    volumes = data.get("volumes", [])
    account = data.get("account_summary", {})
    principals = account.get("Principals", account.get("Users", []))
    result.resources_scanned = len(buckets) + len(groups) + len(volumes) + len(principals) + 1

    root = account.get("RootCredentialReport", {})
    if any(
        _is_true(root.get(key, ""))
        for key in ("access_key_1_active", "access_key_2_active")
    ):
        result.findings.append(
            _finding(
                "aws.iam.root_usage",
                "AWS root account",
                "Root account access key is active",
                Severity.CRITICAL,
                "An active root access key can bypass ordinary identity boundaries.",
                "Deactivate and delete root access keys; use a federated role or named IAM "
                "identity and enforce MFA on the root account.",
                {"active_access_key": True},
            )
        )
    if _is_true(root.get("PasswordEnabled", root.get("password_enabled", ""))) and (
        not _is_true(root.get("MfaActive", root.get("mfa_active", "")))
    ):
        result.findings.append(
            _finding(
                "aws.iam.root_usage",
                "AWS root account",
                "Root account password lacks MFA",
                Severity.HIGH,
                "The root account has a console password without MFA protection.",
                "Enable hardware or virtual MFA for the root user and avoid routine root use.",
                {"password_enabled": True, "mfa_active": False},
            )
        )

    for user in principals:
        policy_documents = [
            policy.get("PolicyDocument", {})
            for policy in user.get("AttachedPolicies", []) + user.get("InlinePolicies", [])
        ]
        for document in policy_documents:
            if _is_wildcard_admin(document):
                result.findings.append(
                    _finding(
                        "aws.iam.wildcard_admin",
                        user.get("UserName", "unknown-user"),
                        "IAM policy contains broad wildcard permissions",
                        Severity.HIGH,
                        "An attached or inline IAM policy allows wildcard actions on all resources.",
                        "Replace unrestricted actions and resources with least-privilege "
                        "permissions and review the policy attachment.",
                        {"wildcard_actions_and_resources": True},
                    )
                )
                break

    for bucket in buckets:
        name = bucket.get("Name", "unknown-bucket")
        acl_public = any(
            grant.get("Grantee", {}).get("URI", "").endswith("/AllUsers")
            or grant.get("Grantee", {}).get("URI", "").endswith("/AuthenticatedUsers")
            for grant in bucket.get("Acl", {}).get("Grants", [])
        )
        policy_public = _has_public_policy(bucket.get("Policy", {}))
        block = bucket.get("PublicAccessBlock", {})
        block_incomplete = len(block) != 4 or not all(
            block.get(key) is True
            for key in (
                "BlockPublicAcls",
                "IgnorePublicAcls",
                "BlockPublicPolicy",
                "RestrictPublicBuckets",
            )
        )
        if acl_public or policy_public or block_incomplete:
            result.findings.append(
                _finding(
                    "aws.s3.public_access",
                    name,
                    "S3 bucket is publicly accessible or lacks complete public access blocks",
                    Severity.CRITICAL if acl_public or policy_public else Severity.HIGH,
                    "Public ACL grants, public bucket policy principals, or incomplete Block "
                    "Public Access settings expose the bucket to unintended access.",
                    "Enable all four Block Public Access settings and remove public ACL grants "
                    "and policy principals.",
                    {
                        "public_acl": acl_public,
                        "public_policy": policy_public,
                        "block_public_access_complete": not block_incomplete,
                    },
                )
            )

    for group in groups:
        group_name = group.get("GroupName") or group.get("GroupId", "unknown-security-group")
        for permission in group.get("IpPermissions", []):
            ports = {22, 3389}
            from_port = permission.get("FromPort")
            to_port = permission.get("ToPort")
            protocol = str(permission.get("IpProtocol", "")).lower()
            exposed_ports = (
                sorted(port for port in ports if from_port is not None and to_port is not None
                       and from_port <= port <= to_port)
                if protocol in {"tcp", "6"}
                else sorted(ports)
                if protocol == "-1"
                else []
            )
            public_ranges = [
                item.get("CidrIp")
                for item in permission.get("IpRanges", [])
                if item.get("CidrIp") == "0.0.0.0/0"
            ]
            public_ranges.extend(
                item.get("CidrIpv6")
                for item in permission.get("Ipv6Ranges", [])
                if item.get("CidrIpv6") == "::/0"
            )
            if exposed_ports and public_ranges:
                result.findings.append(
                    _finding(
                        "aws.ec2.open_admin_port",
                        group_name,
                        "Administrative port is open to the internet",
                        Severity.HIGH,
                        f"Security group ingress exposes port(s) {exposed_ports} to a public CIDR.",
                        "Restrict SSH/RDP access to approved trusted CIDRs or use a private "
                        "administration channel.",
                        {"ports": exposed_ports, "public_cidrs": public_ranges},
                    )
                )

    for volume in volumes:
        if volume.get("Encrypted") is False:
            volume_id = volume.get("VolumeId", "unknown-volume")
            result.findings.append(
                _finding(
                    "aws.ebs.unencrypted",
                    volume_id,
                    "EBS volume is not encrypted",
                    Severity.HIGH,
                    "The EBS volume is explicitly reported as unencrypted.",
                    "Enable EBS encryption by default and migrate this volume to an encrypted "
                    "snapshot or replacement volume.",
                    {"state": volume.get("State"), "availability_zone": volume.get("AvailabilityZone")},
                )
            )
    return result


def scan_aws_live(region_name: str | None = None) -> AuditResult:
    """Collect AWS account configuration using the caller's standard boto3 credentials."""
    try:
        import boto3
        from botocore.exceptions import ClientError

        session = boto3.Session(region_name=region_name)
        iam = session.client("iam")
        s3 = session.client("s3")
        ec2 = session.client("ec2")
        data: dict[str, Any] = {
            "account_summary": {"RootCredentialReport": {}, "Principals": []},
            "buckets": [],
            "security_groups": [],
            "volumes": [],
        }
        generation_started = datetime.now(timezone.utc)
        report = iam.generate_credential_report()
        credential_report: dict[str, Any] | None = None
        for attempt in range(10):
            if attempt:
                time.sleep(1)
            try:
                candidate = iam.get_credential_report()
            except ClientError as exc:
                error_code = exc.response.get("Error", {}).get("Code")
                if error_code not in {
                    "CredentialReportNotPresent",
                    "CredentialReportNotPresentException",
                    "CredentialReportNotReady",
                    "CredentialReportNotReadyException",
                    "ReportNotPresent",
                    "ReportNotPresentException",
                }:
                    raise
                continue
            generated_at = candidate.get("GeneratedTime")
            if generated_at is not None and generated_at.tzinfo is None:
                generated_at = generated_at.replace(tzinfo=timezone.utc)
            if report.get("State") == "COMPLETE" or (
                generated_at is not None
                and generated_at >= generation_started - timedelta(seconds=1)
            ):
                credential_report = candidate
                break
        if credential_report is None:
            raise RuntimeError(
                "AWS credential report did not become available; root-account checks "
                "cannot be completed."
            )
        import csv
        import io

        content = credential_report["Content"].decode("utf-8")
        rows = csv.DictReader(io.StringIO(content))
        root_row = next((row for row in rows if row.get("user") == "<root_account>"), None)
        if root_row is None:
            raise RuntimeError("AWS credential report did not contain the root account.")
        data["account_summary"]["RootCredentialReport"] = {
            **root_row,
            "PasswordEnabled": root_row.get("password_enabled", ""),
            "MfaActive": root_row.get("mfa_active", ""),
        }
        principal_types = (
            ("User", "UserName", "list_users", "Users", "list_attached_user_policies",
             "list_user_policies", "get_user_policy"),
            ("Group", "GroupName", "list_groups", "Groups", "list_attached_group_policies",
             "list_group_policies", "get_group_policy"),
            ("Role", "RoleName", "list_roles", "Roles", "list_attached_role_policies",
             "list_role_policies", "get_role_policy"),
        )
        data["account_summary"]["Principals"] = []
        for kind, name_key, list_method, response_key, attached_method, inline_method, get_inline_method in principal_types:
            for page in iam.get_paginator(list_method).paginate():
                for principal in page.get(response_key, []):
                    name = principal[name_key]
                    principal_data: dict[str, Any] = {
                        "UserName": f"{kind}/{name}",
                        "AttachedPolicies": [],
                        "InlinePolicies": [],
                    }
                    attached = getattr(iam, attached_method)(**{name_key: name}).get(
                        "AttachedPolicies", []
                    )
                    for policy in attached:
                        version = iam.get_policy(PolicyArn=policy["PolicyArn"])["Policy"][
                            "DefaultVersionId"
                        ]
                        document = iam.get_policy_version(
                            PolicyArn=policy["PolicyArn"], VersionId=version
                        )["PolicyVersion"]["Document"]
                        principal_data["AttachedPolicies"].append({"PolicyDocument": document})
                    policy_names = getattr(iam, inline_method)(**{name_key: name}).get(
                        "PolicyNames", []
                    )
                    for policy_name in policy_names:
                        document = getattr(iam, get_inline_method)(
                            **{name_key: name, "PolicyName": policy_name}
                        )["PolicyDocument"]
                        principal_data["InlinePolicies"].append({"PolicyDocument": document})
                    data["account_summary"]["Principals"].append(principal_data)
        for page in s3.get_paginator("list_buckets").paginate():
            for bucket in page.get("Buckets", []):
                name = bucket["Name"]
                item: dict[str, Any] = {
                    "Name": name,
                    "Acl": {"Grants": []},
                    "Policy": {"Statement": []},
                }
                item["Acl"] = s3.get_bucket_acl(Bucket=name)
                try:
                    item["Policy"] = json.loads(s3.get_bucket_policy(Bucket=name)["Policy"])
                except s3.exceptions.NoSuchBucketPolicy:
                    pass
                try:
                    item["PublicAccessBlock"] = s3.get_public_access_block(Bucket=name)[
                        "PublicAccessBlockConfiguration"
                    ]
                except s3.exceptions.NoSuchPublicAccessBlockConfiguration:
                    item["PublicAccessBlock"] = {}
                data["buckets"].append(item)
        for page in ec2.get_paginator("describe_security_groups").paginate():
            data["security_groups"].extend(page.get("SecurityGroups", []))
        for page in ec2.get_paginator("describe_volumes").paginate():
            data["volumes"].extend(page.get("Volumes", []))
    except Exception as exc:
        raise RuntimeError(f"AWS audit failed while collecting account configuration: {exc}") from exc
    return scan_aws_data(data)


def scan_aws_mock() -> AuditResult:
    return scan_aws_data(load_mock_data())
