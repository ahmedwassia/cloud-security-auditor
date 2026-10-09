"""Command-line interface for cloud-security-auditor."""

from __future__ import annotations

from pathlib import Path

import click

from cloud_security_auditor.aws.scanner import scan_aws_live, scan_aws_mock
from cloud_security_auditor.k8s.scanner import scan_cluster, scan_manifests
from cloud_security_auditor.models import AuditResult, Severity
from cloud_security_auditor.reporter.render import render_report, write_report


SEVERITY_ORDER = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
}


def _finish_audit(result: AuditResult, output: str | None, fail_on: str) -> None:
    if output:
        path = write_report(result, output)
        click.echo(f"Report written to {path}")
    else:
        click.echo(render_report(result, "json"), nl=False)

    if result.errors:
        raise click.ClickException(
            f"Audit completed with {len(result.errors)} collection error(s); "
            "review the report and correct access or input issues."
        )
    if fail_on != "never":
        threshold = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
        }[fail_on]
        if any(SEVERITY_ORDER[finding.severity] >= SEVERITY_ORDER[threshold] for finding in result.findings):
            raise click.exceptions.Exit(1)


@click.group()
@click.version_option(package_name="cloud-security-auditor")
def main() -> None:
    """Audit AWS accounts and Kubernetes workloads for security misconfigurations."""


@main.group()
def audit() -> None:
    """Run a security posture audit."""


@audit.command("aws")
@click.option("--mock", "use_mock", is_flag=True, help="Scan the bundled deterministic AWS fixture.")
@click.option("--region", help="AWS region for regional EC2 checks (defaults to the boto3 region).")
@click.option(
    "--output",
    type=click.Path(path_type=Path, dir_okay=False),
    help="Write a .json, .md, or .html report.",
)
@click.option(
    "--fail-on",
    type=click.Choice(["critical", "high", "medium", "low", "never"], case_sensitive=False),
    default="critical",
    show_default=True,
    help="Exit with status 1 if findings meet or exceed this severity.",
)
def audit_aws(use_mock: bool, region: str | None, output: Path | None, fail_on: str) -> None:
    """Audit S3, IAM, security groups, and EBS configuration."""
    try:
        result = scan_aws_mock() if use_mock else scan_aws_live(region_name=region)
        _finish_audit(result, str(output) if output else None, fail_on.lower())
    except (RuntimeError, ValueError, OSError) as exc:
        raise click.ClickException(str(exc)) from exc


@audit.command("k8s")
@click.option(
    "--manifests",
    type=click.Path(path_type=Path, exists=True, file_okay=True, dir_okay=True),
    help="Scan one Kubernetes YAML file or a directory tree of YAML files.",
)
@click.option("--cluster", "use_cluster", is_flag=True, help="Scan workloads in the current kubeconfig context.")
@click.option(
    "--output",
    type=click.Path(path_type=Path, dir_okay=False),
    help="Write a .json, .md, or .html report.",
)
@click.option(
    "--fail-on",
    type=click.Choice(["critical", "high", "medium", "low", "never"], case_sensitive=False),
    default="critical",
    show_default=True,
    help="Exit with status 1 if findings meet or exceed this severity.",
)
def audit_k8s(
    manifests: Path | None, use_cluster: bool, output: Path | None, fail_on: str
) -> None:
    """Audit Kubernetes manifests or live workloads."""
    if bool(manifests) == use_cluster:
        raise click.UsageError("Choose exactly one of --manifests PATH or --cluster.")
    try:
        if use_cluster:
            result = scan_cluster()
        elif manifests is not None:
            result = scan_manifests(manifests)
        else:
            raise click.UsageError("Choose exactly one of --manifests PATH or --cluster.")
        _finish_audit(result, str(output) if output else None, fail_on.lower())
    except (RuntimeError, ValueError, OSError) as exc:
        raise click.ClickException(str(exc)) from exc


if __name__ == "__main__":
    main()
