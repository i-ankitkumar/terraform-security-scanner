import os

from tfscan.core import scan

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def _basename(finding):
    return os.path.basename(finding.file_path)


def test_insecure_fixture_triggers_expected_rules():
    result = scan(FIXTURES)
    triggered = {f.rule_id for f in result.findings if _basename(f) == "insecure.tf"}

    expected_subset = {
        "TF001",  # open security group
        "TF002",  # public S3 ACL
        "TF004",  # unencrypted EBS
        "TF005",  # IAM wildcard action
        "TF006",  # IAM wildcard resource
        "TF007",  # azure public storage
        "TF008",  # azure outdated TLS
        "TF011",  # hardcoded secret
        "TF012",  # missing tags
        "TF013",  # unpinned provider
    }
    missing = expected_subset - triggered
    assert not missing, f"Expected rules did not fire on insecure.tf: {missing}"


def test_secure_fixture_is_much_cleaner_than_insecure():
    result = scan(FIXTURES)
    secure_findings = [f for f in result.findings if _basename(f) == "secure.tf"]
    insecure_findings = [f for f in result.findings if _basename(f) == "insecure.tf"]

    # secure.tf isn't necessarily zero-finding (rules are conservative on purpose),
    # but it must be dramatically cleaner than the deliberately broken fixture.
    assert len(secure_findings) < len(insecure_findings)
    assert not any(f.severity == "critical" for f in secure_findings)


def test_scan_empty_directory_returns_no_findings(tmp_path):
    result = scan(str(tmp_path))
    assert result.findings == []
    assert result.config.resources == []


def test_worst_severity_reflects_highest_priority_finding():
    result = scan(FIXTURES)
    assert result.worst_severity() == "critical"
