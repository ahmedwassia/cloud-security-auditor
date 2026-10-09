"""Kubernetes workload security checks for YAML manifests and live clusters."""

from __future__ import annotations

import hashlib
import json
import posixpath
from pathlib import Path
from typing import Any, Iterable

import yaml

from cloud_security_auditor.cis.mappings import controls_for_rule
from cloud_security_auditor.models import AuditResult, Finding, Severity


SENSITIVE_HOST_PATHS = (
    "/",
    "/etc",
    "/proc",
    "/sys",
    "/dev",
    "/var/run",
    "/var/lib/docker",
    "/var/lib/kubelet",
)
DANGEROUS_CAPABILITIES = {
    "ALL",
    "DAC_OVERRIDE",
    "DAC_READ_SEARCH",
    "MKNOD",
    "NET_BROADCAST",
    "NET_ADMIN",
    "NET_RAW",
    "SETGID",
    "SETUID",
    "SYS_ADMIN",
    "SYS_MODULE",
    "SYS_PTRACE",
    "SYS_RAWIO",
    "SYS_TIME",
}


def _finding(
    rule_id: str,
    resource: str,
    title: str,
    severity: Severity,
    description: str,
    remediation: str,
    evidence: dict[str, Any],
) -> Finding:
    identity = json.dumps(
        {"resource": resource, "title": title, "evidence": evidence},
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return Finding(
        finding_id=f"{rule_id}:{hashlib.sha256(identity.encode()).hexdigest()[:16]}",
        rule_id=rule_id,
        source="k8s",
        resource=resource,
        title=title,
        severity=severity,
        description=description,
        remediation=remediation,
        cis_controls=controls_for_rule(rule_id),
        evidence=evidence,
    )


def _pod_spec(obj: dict[str, Any]) -> tuple[dict[str, Any] | None, str]:
    kind = str(obj.get("kind", "Unknown"))
    metadata = obj.get("metadata") or {}
    name = metadata.get("name", "unnamed")
    namespace = metadata.get("namespace", "default")
    resource = f"{kind}/{namespace}/{name}"
    if kind == "Pod":
        spec = obj.get("spec")
    elif kind == "CronJob":
        spec = (((obj.get("spec") or {}).get("jobTemplate") or {}).get("spec") or {}).get(
            "template", {}
        ).get("spec")
    else:
        spec = (((obj.get("spec") or {}).get("template") or {}).get("spec"))
    return (spec if isinstance(spec, dict) else None), resource


def scan_k8s_objects(objects: Iterable[dict[str, Any]]) -> AuditResult:
    result = AuditResult(platform="k8s")
    for obj in objects:
        spec, resource = _pod_spec(obj)
        if spec is None:
            continue
        result.resources_scanned += 1
        pod_context = spec.get("securityContext") or {}
        volumes = spec.get("volumes") or []
        containers = [
            (container, "container")
            for container in spec.get("containers", [])
        ] + [
            (container, "initContainer")
            for container in spec.get("initContainers", [])
        ]
        for container, container_type in containers:
            name = container.get("name", "unnamed")
            target = f"{resource}/{container_type}/{name}"
            container_context = container.get("securityContext") or {}
            if container_context.get("privileged") is True:
                result.findings.append(
                    _finding(
                        "k8s.container.privileged",
                        target,
                        "Container runs in privileged mode",
                        Severity.CRITICAL,
                        "Privileged mode grants the container broad host-level capabilities.",
                        "Set privileged: false and enforce the restricted Pod Security Standard.",
                        {"privileged": True},
                    )
                )

            run_as_non_root = container_context.get(
                "runAsNonRoot", pod_context.get("runAsNonRoot")
            )
            run_as_user = container_context.get("runAsUser", pod_context.get("runAsUser"))
            if run_as_user == 0 or run_as_non_root is not True:
                result.findings.append(
                    _finding(
                        "k8s.container.root",
                        target,
                        "Container does not enforce non-root execution",
                        Severity.HIGH,
                        "The effective security context permits root execution or does not "
                        "require a non-root user.",
                        "Set runAsNonRoot: true and specify a non-zero runAsUser where the "
                        "image requires an explicit UID.",
                        {"runAsNonRoot": run_as_non_root, "runAsUser": run_as_user},
                    )
                )

            limits = ((container.get("resources") or {}).get("limits") or {})
            missing_limits = [key for key in ("cpu", "memory") if not limits.get(key)]
            if missing_limits:
                result.findings.append(
                    _finding(
                        "k8s.container.resource_limits",
                        target,
                        "Container is missing CPU or memory limits",
                        Severity.MEDIUM,
                        "Without explicit CPU and memory limits, a workload can consume "
                        "unbounded node resources.",
                        "Set appropriate resources.limits.cpu and resources.limits.memory for "
                        "the container.",
                        {"missing_limits": missing_limits},
                    )
                )

            capabilities = (
                (container_context.get("capabilities") or {}).get("add") or []
            )
            dangerous = sorted(
                {str(capability).upper().removeprefix("CAP_") for capability in capabilities}
                & DANGEROUS_CAPABILITIES
            )
            if "NET_RAW" in dangerous:
                result.findings.append(
                    _finding(
                        "k8s.container.net_raw_capability",
                        target,
                        "Container adds the NET_RAW Linux capability",
                        Severity.HIGH,
                        "NET_RAW can enable low-level network access, including raw packet "
                        "operations.",
                        "Remove NET_RAW from the container's added capabilities.",
                        {"capabilities": ["NET_RAW"]},
                    )
                )
                dangerous.remove("NET_RAW")
            if dangerous:
                result.findings.append(
                    _finding(
                        "k8s.container.dangerous_capability",
                        target,
                        "Container adds dangerous Linux capabilities",
                        Severity.HIGH,
                        f"The container requests dangerous capabilities: {', '.join(dangerous)}.",
                        "Drop all capabilities and add back only the minimum explicitly required.",
                        {"capabilities": dangerous},
                    )
                )
        for volume in volumes:
            host_path = (volume.get("hostPath") or {}).get("path")
            if not host_path:
                continue
            normalized = posixpath.normpath(str(host_path))
            sensitive = any(
                normalized == base
                or (base != "/" and normalized.startswith(base.rstrip("/") + "/"))
                for base in SENSITIVE_HOST_PATHS
            )
            mounts = [
                {
                    "container": container.get("name", "unnamed"),
                    "mount_path": mount.get("mountPath"),
                }
                for container, _ in containers
                for mount in (container.get("volumeMounts") or [])
                if mount.get("name") == volume.get("name")
            ]
            if sensitive and mounts:
                result.findings.append(
                    _finding(
                        "k8s.volume.sensitive_hostpath",
                        f"{resource}/volume/{volume.get('name', 'unnamed')}",
                        "Workload mounts a sensitive host path",
                        Severity.HIGH,
                        f"The hostPath volume exposes sensitive node path {host_path!r}.",
                        "Remove the hostPath volume or replace it with a narrowly scoped, "
                        "read-only alternative.",
                        {
                            "volume": volume.get("name"),
                            "host_path": host_path,
                            "mounts": mounts,
                        },
                    )
                )
    return result


def scan_manifests(path: str | Path) -> AuditResult:
    """Scan a YAML file or recursively scan YAML files in a directory."""
    root = Path(path)
    if not root.exists():
        raise FileNotFoundError(f"Manifest path does not exist: {root}")
    if root.is_file():
        manifest_paths = [root] if root.suffix.lower() in {".yaml", ".yml"} else []
    else:
        manifest_paths = sorted(
            item for item in root.rglob("*") if item.is_file() and item.suffix.lower() in {".yaml", ".yml"}
        )
    if not manifest_paths:
        raise ValueError(f"No YAML manifest files found at: {root}")

    objects: list[dict[str, Any]] = []
    errors: list[str] = []
    for manifest_path in manifest_paths:
        try:
            with manifest_path.open("r", encoding="utf-8") as stream:
                for document in yaml.safe_load_all(stream):
                    if document is None:
                        continue
                    if not isinstance(document, dict):
                        raise ValueError("document root must be a YAML mapping")
                    if document.get("kind") == "List":
                        items = document.get("items", [])
                        if not isinstance(items, list):
                            raise ValueError("Kubernetes List items must be a sequence")
                        if any(not isinstance(item, dict) for item in items):
                            raise ValueError("Kubernetes List contains a non-mapping item")
                        objects.extend(items)
                    else:
                        objects.append(document)
        except (OSError, yaml.YAMLError, ValueError) as exc:
            errors.append(f"{manifest_path}: {exc}")
    result = scan_k8s_objects(objects)
    result.errors.extend(errors)
    if errors and not objects:
        raise ValueError("Unable to parse any Kubernetes manifests: " + "; ".join(errors))
    return result


def scan_cluster() -> AuditResult:
    """Audit workloads using kubeconfig credentials or in-cluster service credentials."""
    from kubernetes import client, config
    from kubernetes.config.config_exception import ConfigException

    try:
        try:
            config.load_kube_config()
        except ConfigException as kubeconfig_error:
            try:
                config.load_incluster_config()
            except ConfigException as in_cluster_error:
                raise RuntimeError(
                    "Neither kubeconfig nor in-cluster Kubernetes credentials are available: "
                    f"{kubeconfig_error}; {in_cluster_error}"
                ) from in_cluster_error
        api = client.AppsV1Api()
        batch_api = client.BatchV1Api()
        core_api = client.CoreV1Api()
        resources = []
        for listing in (
            api.list_deployment_for_all_namespaces(),
            api.list_stateful_set_for_all_namespaces(),
            api.list_daemon_set_for_all_namespaces(),
            api.list_replica_set_for_all_namespaces(),
            batch_api.list_job_for_all_namespaces(),
            batch_api.list_cron_job_for_all_namespaces(),
            core_api.list_pod_for_all_namespaces(),
            core_api.list_replication_controller_for_all_namespaces(),
        ):
            resources.extend(
                client.ApiClient().sanitize_for_serialization(item) for item in listing.items
            )
    except Exception as exc:
        raise RuntimeError(f"Kubernetes cluster audit failed: {exc}") from exc
    result = scan_k8s_objects(resources)
    result.resources_scanned = len(resources)
    return result
