import json

from click.testing import CliRunner

from cloud_security_auditor.cli import main
from cloud_security_auditor.models import AuditResult, Finding, Severity
from cloud_security_auditor.reporter.render import render_html, render_markdown, render_json


def test_json_report_has_severity_and_scoped_compliance_summary():
    result = AuditResult(platform="aws")
    result.findings.append(
        Finding(
            finding_id="sample",
            rule_id="aws.iam.root_usage",
            source="aws",
            resource="root",
            title="Root finding",
            severity=Severity.CRITICAL,
            description="Description",
            remediation="Remediation",
            cis_controls=("CIS control",),
        )
    )

    report = json.loads(render_json(result))

    assert report["summary"]["by_severity"]["Critical"] == 1
    assert report["compliance"]["controls_failed"] == 1
    assert "not a full benchmark certification" in report["compliance"]["scope_note"]


def test_collection_errors_make_compliance_percentage_unavailable():
    result = AuditResult(platform="k8s", errors=["manifest could not be parsed"])

    assert result.compliance_summary()["percentage"] is None
    assert "Unavailable" in render_markdown(result)


def test_markdown_and_html_reports_render_findings_and_escape_html():
    result = AuditResult(platform="k8s")
    result.findings.append(
        Finding(
            finding_id="unsafe",
            rule_id="k8s.container.privileged",
            source="k8s",
            resource="<script>alert(1)</script>",
            title="Unsafe | container",
            severity=Severity.HIGH,
            description="Description",
            remediation="Set privileged: false",
        )
    )

    markdown = render_markdown(result)
    html = render_html(result)

    assert "Unsafe \\| container" in markdown
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "CIS compliance" in html


def test_cli_writes_requested_report_and_supports_fail_threshold(tmp_path):
    output = tmp_path / "audit.json"
    runner = CliRunner()

    failed = runner.invoke(
        main,
        ["audit", "aws", "--mock", "--output", str(output), "--fail-on", "high"],
    )
    assert failed.exit_code == 1
    assert output.exists()
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["summary"]["findings"] > 0

    passed = runner.invoke(
        main, ["audit", "aws", "--mock", "--fail-on", "never"]
    )
    assert passed.exit_code == 0
    assert json.loads(passed.output)["platform"] == "aws"
