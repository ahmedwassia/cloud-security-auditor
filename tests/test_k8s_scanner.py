from pathlib import Path

from cloud_security_auditor.k8s.scanner import scan_manifests


FIXTURES = Path(__file__).parent / "fixtures" / "k8s"


def test_manifest_scanner_detects_risky_container_settings():
    result = scan_manifests(FIXTURES / "vulnerable.yaml")

    assert result.resources_scanned == 2
    assert {finding.rule_id for finding in result.findings} == {
        "k8s.container.privileged",
        "k8s.container.root",
        "k8s.container.net_raw_capability",
        "k8s.container.resource_limits",
        "k8s.volume.sensitive_hostpath",
        "k8s.container.dangerous_capability",
    }
    limits = next(
        finding for finding in result.findings if finding.rule_id == "k8s.container.resource_limits"
    )
    assert limits.evidence["missing_limits"] == ["memory"]
    hostpath = next(
        finding for finding in result.findings
        if finding.rule_id == "k8s.volume.sensitive_hostpath"
    )
    assert hostpath.evidence["mounts"] == [
        {"container": "api", "mount_path": "/runtime"}
    ]


def test_secure_manifest_passes_all_mapped_cis_controls():
    result = scan_manifests(FIXTURES / "secure.yaml")

    assert result.findings == []
    assert result.compliance_summary()["percentage"] == 100.0


def test_directory_scan_includes_nested_yaml_files(tmp_path):
    nested = tmp_path / "nested"
    nested.mkdir()
    (nested / "workload.yaml").write_text(
        (FIXTURES / "secure.yaml").read_text(encoding="utf-8"), encoding="utf-8"
    )

    result = scan_manifests(tmp_path)

    assert result.resources_scanned == 1
    assert result.findings == []
