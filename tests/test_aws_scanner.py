import json
from pathlib import Path

from cloud_security_auditor.aws.scanner import scan_aws_data, scan_aws_mock


FIXTURE = Path(__file__).parent / "fixtures" / "aws" / "mock_responses.json"


def test_aws_scanner_detects_required_findings_and_ignores_private_resources():
    result = scan_aws_data(json.loads(FIXTURE.read_text(encoding="utf-8")))

    assert result.resources_scanned == 7
    assert len({finding.finding_id for finding in result.findings}) == len(result.findings)
    assert {finding.rule_id for finding in result.findings} == {
        "aws.iam.root_usage",
        "aws.iam.wildcard_admin",
        "aws.s3.public_access",
        "aws.ec2.open_admin_port",
        "aws.ebs.unencrypted",
    }
    by_rule = {finding.rule_id: finding for finding in result.findings}
    assert by_rule["aws.iam.wildcard_admin"].resource == "Role/UnrestrictedDeployment"
    assert by_rule["aws.ec2.open_admin_port"].evidence["ports"] == [22]
    assert by_rule["aws.ebs.unencrypted"].resource == "vol-unencrypted"
    assert by_rule["aws.s3.public_access"].cis_controls


def test_bundled_mock_fixture_is_reproducibly_vulnerable():
    result = scan_aws_mock()

    assert result.findings
    assert result.compliance_summary()["controls_failed"] == 5
