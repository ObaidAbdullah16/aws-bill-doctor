import json

from billdoctor.cli import main
from billdoctor.models import REGISTRY, Finding
from billdoctor.report import to_csv, to_html, to_markdown
from billdoctor.scanner import ScanResult, run_scan

REGION = "ap-south-1"


def test_registry_has_twelve_checks():
    from billdoctor import checks  # noqa: F401
    assert len(REGISTRY) == 12


def test_savings_counted_once_per_resource(now):
    r = ScanResult(account_id="1", account_label="", regions=[REGION], started_at=now)
    r.findings = [
        Finding("EC2-003", "idle", REGION, "ec2-instance", "i-1", "", "", 70, 70),
        Finding("EC2-004", "old gen", REGION, "ec2-instance", "i-1", "", "", 70, 7),
        Finding("EC2-001", "eip", REGION, "elastic-ip", "eip-1", "", "", 3.65, 3.65),
    ]
    assert r.monthly_savings == 73.65


def test_empty_account_scan_and_reports(aws):
    r = run_scan(aws, [REGION])
    assert r.findings == [] and r.errors == []
    html = to_html(r)
    assert "No quantified savings found" in html
    assert to_csv(r).startswith("priority,check_id")
    assert "Estimated savings: $0.00" in to_markdown(r)


def test_report_only_claims_checks_that_ran(aws, monkeypatch):
    from botocore.exceptions import ClientError

    from billdoctor import models

    def denied(ctx):
        raise ClientError({"Error": {"Code": "AccessDenied", "Message": "nope"}}, "DescribeAddresses")
        yield  # pragma: no cover

    monkeypatch.setitem(models.REGISTRY, "EC2-001", models.CheckInfo("EC2-001", "t", "EC2", "w", denied))
    r = run_scan(aws, [REGION], only=["EBS-001", "EC2-001"])
    assert r.checks_run == ["EBS-001", "EC2-001"]
    assert r.clean_checks == ["EBS-001"]  # EC2-001 failed: it must not be reported as "no issues"
    html = to_html(r)
    assert "ran 2 read-only checks" in html
    assert "No issues for: EBS-001." in html and "EC2-002" not in html


def test_access_denied_is_recorded_not_fatal(aws, monkeypatch):
    from botocore.exceptions import ClientError

    from billdoctor import models

    def denied(ctx):
        raise ClientError({"Error": {"Code": "AccessDenied", "Message": "nope"}}, "DescribeVolumes")
        yield  # pragma: no cover

    monkeypatch.setitem(models.REGISTRY, "EBS-001", models.CheckInfo("EBS-001", "t", "EC2", "w", denied))
    r = run_scan(aws, [REGION], only=["EBS-001"])
    assert r.errors and r.errors[0]["error"].startswith("AccessDenied")


def test_demo_end_to_end(tmp_path):
    assert main(["demo", "--out", str(tmp_path)]) == 0
    data = json.loads((tmp_path / "findings.json").read_text())
    assert data["synthetic_data"] is True
    found = {f["check_id"] for f in data["findings"]}
    assert found == set(REGISTRY), f"every check should fire in the demo, missing {set(REGISTRY) - found}"
    assert data["errors"] == []
    assert "SYNTHETIC DEMO DATA" in (tmp_path / "report.html").read_text()


def _policy_actions() -> set[str]:
    import importlib.resources as res
    policy = json.loads(res.files("billdoctor").joinpath("data/billdoctor-readonly.json").read_text())
    return {a for s in policy["Statement"] for a in s["Action"]}


def test_policy_is_read_only():
    actions = _policy_actions()
    assert all(":" in a and not a.endswith("*") for a in actions), "no wildcards in the client policy"
    assert not any(a.split(":")[1].startswith(("Delete", "Put", "Create", "Modify")) for a in actions)


# boto3 operation -> IAM action, where the names differ
IAM_NAME = {("s3", "ListBuckets"): "s3:ListAllMyBuckets",
            ("s3", "GetBucketLifecycleConfiguration"): "s3:GetLifecycleConfiguration"}
IAM_PREFIX = {"elbv2": "elasticloadbalancing", "elb": "elasticloadbalancing"}
NEEDS_NO_PERMISSION = {"sts:GetCallerIdentity"}


def test_policy_covers_every_api_the_scan_calls(now):
    """Record every AWS call a full demo scan makes and check the client policy allows it,
    so a new check can never ship with an AccessDenied waiting at the client."""
    import boto3
    from moto import mock_aws

    from billdoctor.demo import PRIMARY, SECONDARY, seed

    called: set[str] = set()

    def record(model, **_):
        svc = model.service_model.service_name
        called.add(IAM_NAME.get((svc, model.name), f"{IAM_PREFIX.get(svc, svc)}:{model.name}"))

    with mock_aws():
        seed(now)
        session = boto3.Session(region_name=PRIMARY)
        session.events.register("before-call", record)
        result = run_scan(session, [PRIMARY, SECONDARY])
    assert len({f.check_id for f in result.findings}) == len(REGISTRY)  # every check really ran
    missing = called - _policy_actions() - NEEDS_NO_PERMISSION
    assert not missing, f"add to policies/billdoctor-readonly.json and both client-access templates: {sorted(missing)}"


def test_client_templates_match_the_policy():
    import re
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    assert (root / "policies/billdoctor-readonly.json").read_text() == (root / "billdoctor/data/billdoctor-readonly.json").read_text()
    cfn = (root / "client-access/cloudformation-readonly-role.yaml").read_text()
    cfn_actions = set(re.findall(r"\b([a-z0-9-]+:[A-Z][A-Za-z]+)\b", cfn)) - {"sts:AssumeRole", "sts:ExternalId"}
    security = json.loads((root / "policies/security-check-readonly.json").read_text())
    security_actions = {a for s in security["Statement"] for a in s["Action"]}
    assert cfn_actions == _policy_actions() | security_actions
    tf = (root / "client-access/terraform/main.tf").read_text()
    assert "policies/billdoctor-readonly.json" in tf and "OptionalCostExplorer" in tf


def test_unknown_check_id_is_an_error(capsys):
    assert main(["scan", "--checks", "EBS-001,EBS-999"]) == 2
    assert "EBS-999" in capsys.readouterr().err
