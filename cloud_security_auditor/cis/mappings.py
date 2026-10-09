"""Mappings from auditor rule identifiers to CIS benchmark controls."""

from dataclasses import dataclass


@dataclass(frozen=True)
class Control:
    control_id: str
    title: str
    benchmark: str
    remediation: str


CONTROLS: dict[str, Control] = {
    "aws.s3.public_access": Control(
        "2.1.5",
        "Ensure S3 buckets are configured with Block Public Access",
        "CIS AWS Foundations Benchmark v1.5.0",
        "Enable all four account- and bucket-level S3 Block Public Access settings; "
        "remove public bucket ACL grants and policy statements.",
    ),
    "aws.iam.root_usage": Control(
        "1.1",
        "Avoid the use of the root account",
        "CIS AWS Foundations Benchmark v1.5.0",
        "Use a named IAM identity or federated role for day-to-day work and protect "
        "root credentials with MFA.",
    ),
    "aws.iam.wildcard_admin": Control(
        "1.16",
        "Ensure IAM policies that allow full administrative privileges are not attached",
        "CIS AWS Foundations Benchmark v1.5.0",
        "Replace wildcard actions and resources with the least-privilege permissions "
        "required by the workload.",
    ),
    "aws.ec2.open_admin_port": Control(
        "5.2",
        "Ensure no security groups allow ingress from 0.0.0.0/0 to remote administration ports",
        "CIS AWS Foundations Benchmark v1.5.0",
        "Restrict SSH and RDP ingress to approved trusted CIDRs or private access paths.",
    ),
    "aws.ebs.unencrypted": Control(
        "2.2.1",
        "Ensure EBS volume encryption is enabled",
        "CIS AWS Foundations Benchmark v1.5.0",
        "Enable default EBS encryption and migrate or snapshot-recreate unencrypted volumes.",
    ),
    "k8s.container.privileged": Control(
        "5.2.1",
        "Minimize the admission of privileged containers",
        "CIS Kubernetes Benchmark v1.8.0",
        "Set securityContext.privileged to false and enforce the restricted Pod Security Standard.",
    ),
    "k8s.container.root": Control(
        "5.2.6",
        "Minimize the admission of root containers",
        "CIS Kubernetes Benchmark v1.8.0",
        "Set runAsNonRoot: true and use a non-zero runAsUser at the pod or container level.",
    ),
    "k8s.container.net_raw_capability": Control(
        "5.2.7",
        "Minimize the admission of containers with the NET_RAW capability",
        "CIS Kubernetes Benchmark v1.8.0",
        "Remove NET_RAW from the container's added capabilities and enforce the restricted "
        "Pod Security Standard.",
    ),
    "k8s.volume.sensitive_hostpath": Control(
        "5.2.11",
        "Minimize the admission of hostPath volumes",
        "CIS Kubernetes Benchmark v1.8.0",
        "Remove hostPath mounts where possible; otherwise allow only explicitly approved, "
        "read-only paths.",
    ),
    "k8s.container.dangerous_capability": Control(
        "5.2.8",
        "Minimize the admission of containers with added capabilities",
        "CIS Kubernetes Benchmark v1.8.0",
        "Drop all Linux capabilities and add back only capabilities explicitly required.",
    ),
}


def controls_for_rule(rule_id: str) -> tuple[str, ...]:
    control = CONTROLS.get(rule_id)
    if control is None:
        return ()
    return (f"{control.benchmark} {control.control_id}: {control.title}",)
