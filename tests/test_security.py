import datetime as dt
import json
from pathlib import Path

import pytest

from billdoctor.cli import main
from billdoctor.scanner import ScanResult
from billdoctor.security import prowler as prowler_runner
from billdoctor.security.assess import FAIL, MANUAL, NO_RESOURCES, NOT_EVALUATED, PASS, assess, compare, grade
from billdoctor.security.controls import CONTROLS, GROUPS, SEVERITY_WEIGHT, control_for_check, prowler_checks
from billdoctor.security.demo import run_demo
from billdoctor.security.extras import ci_oidc, spend_alerts
from billdoctor.security.healthcheck import write_bundle
from billdoctor.security.ocsf import CheckResult, cis_refs, load, parse_item
from billdoctor.security.report import to_csv, to_html, to_markdown

ROOT = Path(__file__).resolve().parents[1]


def ocsf(check, status="FAIL", uid="arn:aws:s3:::b", region="ap-south-1", suppressed=False, cis=None):
    return {
        "metadata": {"event_code": check, "product": {"version": "5.47.0"}},
        "status_code": status, "status": "Suppressed" if suppressed else "New", "status_detail": f"{check} {status}",
        "severity": "High", "resources": [{"uid": uid, "region": region, "type": "AwsS3Bucket", "name": uid.rsplit(":", 1)[-1]}],
        "cloud": {"account": {"uid": "111122223333"}, "region": region},
        "unmapped": {"compliance": {"CIS-3.0": cis or [], "CIS-6.0": ["9.9"]} if cis else {}},
    }


def cr(check, status="FAIL", **kw):
    return parse_item(ocsf(check, status, **kw))


# ------------------------------------------------------------------ controls
def test_twenty_five_controls_in_five_groups():
    assert len(CONTROLS) == 25
    assert {c.group for c in CONTROLS} == set(GROUPS)
    assert len({c.id for c in CONTROLS}) == 25
    for c in CONTROLS:
        assert c.severity in SEVERITY_WEIGHT
        assert c.why and c.title
        assert c.prowler or c.native, c.id
        assert c.fix.terraform or c.fix.cli or c.fix.console, c.id


def test_each_prowler_check_belongs_to_one_control():
    checks = prowler_checks()
    assert len(checks) == len(set(checks)) == len(control_for_check())
    assert all(c.islower() and " " not in c for c in checks)


def test_demo_fixture_only_uses_known_checks():
    known = set(prowler_checks())
    for name in ("security-demo.json", "security-demo-after.json"):
        data = json.loads((ROOT / "billdoctor" / "data" / name).read_text())
        assert {i["metadata"]["event_code"] for i in data["prowler"]} <= known
        assert "demo-only" not in json.dumps(data)          # fake secret values never reach the fixture


# ------------------------------------------------------------------ OCSF parsing
def test_parse_item_and_skip_bad_items(tmp_path):
    good = ocsf("guardduty_is_enabled")
    p = tmp_path / "out.ocsf.json"
    p.write_text(json.dumps([good, {"metadata": {}}, "junk", ocsf("x", "INFO")]))
    rs = load(p)
    assert len(rs) == 1 and rs[0].check_id == "guardduty_is_enabled" and rs[0].account_id == "111122223333"
    nd = tmp_path / "nd.json"
    nd.write_text(json.dumps(good) + "\n" + json.dumps(ocsf("guardduty_is_enabled", "PASS")) + "\n")
    assert [r.status for r in load(nd)] == ["FAIL", "PASS"]
    assert load(tmp_path / "out.ocsf.json")[0].prowler_version == "5.47.0"


def test_muted_and_cis_refs():
    r = cr("guardduty_is_enabled", suppressed=True, cis=["4.15"])
    assert r.muted
    assert cis_refs([r]) == {"guardduty_is_enabled": ["CIS-6.0 9.9"]}   # newest CIS version wins


# ------------------------------------------------------------------ assessment
def status_of(a, cid):
    return next(r for r in a.results if r.control.id == cid).status


def test_control_statuses():
    a = assess([
        cr("guardduty_is_enabled", "FAIL"),                       # LD-02 fail
        cr("ec2_ebs_default_encryption", "PASS"),                  # DA-03 pass (both checks not required)
        cr("rds_instance_storage_encrypted", "PASS"),
        cr("rds_instance_deletion_protection", "FAIL"),            # DA-04: any fail wins
        cr("iam_user_mfa_enabled_console_access", "MANUAL"),       # ID-02 review
        CheckResult("native:ci_oidc", "MANUAL", "global", "x", "AwsIamOidcProvider", "x", "confirm"),
    ])
    assert status_of(a, "LD-02") == FAIL
    assert status_of(a, "DA-03") == PASS
    assert status_of(a, "DA-04") == FAIL
    assert status_of(a, "ID-02") == MANUAL
    assert status_of(a, "SP-03") == MANUAL
    assert status_of(a, "NC-02") == NO_RESOURCES          # resource-scoped: nothing found
    assert status_of(a, "ID-01") == NOT_EVALUATED         # account-scoped: no result is not a pass
    assert a.account_id == "111122223333"


def test_errors_turn_no_resources_into_not_evaluated():
    a = assess([], errors=[{"check": "native:spend_alerts", "region": "global", "error": "AccessDenied"}])
    assert status_of(a, "LD-05") == NOT_EVALUATED


def test_score_is_severity_weighted():
    a = assess([cr("guardduty_is_enabled", "FAIL"),        # high 6
                cr("accessanalyzer_enabled", "PASS"),      # medium 3
                cr("iam_password_policy_minimum_length_14", "PASS")])  # low 1
    assert a.score == round(100 * 4 / 10)
    assert a.grade == "D"
    assert [grade(s) for s in (90, 89, 75, 60, 40, 39)] == ["A", "B", "B", "C", "D", "F"]


def test_muted_findings_do_not_fail_a_control():
    a = assess([cr("guardduty_is_enabled", "FAIL", suppressed=True)])
    r = next(r for r in a.results if r.control.id == "LD-02")
    assert r.status == PASS and len(r.muted) == 1


def test_top_risks_ranked_by_severity_then_count():
    a = assess([cr("guardduty_is_enabled"), cr("s3_bucket_public_access", uid="arn:aws:s3:::a"),
                cr("s3_bucket_public_access", uid="arn:aws:s3:::b"), cr("accessanalyzer_enabled")])
    assert [r.control.id for r in a.top_risks()] == ["DA-02", "LD-02", "ID-07"]


# ------------------------------------------------------------------ demo, reports, retest
def test_demo_before_and_after():
    before, after = run_demo(stage="before"), run_demo(stage="after")
    assert before.synthetic and after.synthetic
    assert before.score < 50 <= 90 <= after.score
    r = compare(before.to_dict(), after.to_dict())
    assert "SP-01" in r["fixed"] and r["new_failures"] == []


def test_reports_render():
    a = run_demo()
    html = to_html(a)
    assert "SYNTHETIC DEMO DATA" in html and "Top risks" in html and "not legal advice" not in html
    assert to_csv(a).startswith("control_id,control,severity")
    assert f"**Score: {a.score}/100" in to_markdown(a)
    dpdp = run_demo(profile="dpdp")
    h = to_html(dpdp)
    assert "DPDP technical safeguards check" in h and "not legal advice" in h and "72-hour" in h


def test_cli_demo_and_lists(tmp_path, capsys):
    assert main(["security", "demo", "--out", str(tmp_path / "s")]) == 0
    assert (tmp_path / "s" / "report.html").exists() and (tmp_path / "s" / "retest" / "report.html").exists()
    assert "Retest after fixes" in (tmp_path / "s" / "retest" / "report.html").read_text()
    assert main(["security", "controls"]) == 0
    assert main(["security", "policy"]) == 0
    assert '"DenyReadingData"' in capsys.readouterr().out
    assert main(["security", "compare", "--before", str(tmp_path / "s" / "findings.json"),
                 "--after", str(tmp_path / "s" / "retest" / "findings.json")]) == 0


def test_cli_report_from_prowler_file(tmp_path):
    f = tmp_path / "p.ocsf.json"
    f.write_text(json.dumps([ocsf("guardduty_is_enabled"), ocsf("accessanalyzer_enabled", "PASS")]))
    assert main(["security", "report", "--prowler-json", str(f), "--out", str(tmp_path / "r"), "--dpdp"]) == 0
    data = json.loads((tmp_path / "r" / "findings.json").read_text())
    assert data["profile"] == "dpdp" and data["status_counts"]["fail"] == 1
    assert any("--native" in n for n in data["notes"])


def test_health_check_bundle(tmp_path):
    cost = ScanResult(account_id="1", account_label="Acme", regions=["ap-south-1"], started_at=dt.datetime.now(dt.timezone.utc))
    files = write_bundle(cost, run_demo(), str(tmp_path))
    index = (tmp_path / "index.html").read_text()
    assert "AWS Health Check" in index and "security/report.html" in index and "cost/report.html" in index
    assert len(files) == 9


# ------------------------------------------------------------------ Prowler command
def test_prowler_command_and_redaction():
    cmd = prowler_runner.build_command("out", regions=["ap-south-1"], role_arn="arn:aws:iam::1:role/R", external_id="s3cr3t")
    assert cmd[:2] == ["prowler", "aws"] and "json-ocsf" in cmd
    assert set(prowler_checks()) <= set(cmd)
    assert cmd[cmd.index("--external-id") + 1] == "s3cr3t"
    assert "s3cr3t" not in prowler_runner.redact(cmd)


def test_scan_without_prowler_explains_how_to_install(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(prowler_runner.shutil, "which", lambda _: None)
    assert main(["security", "scan", "--out", str(tmp_path)]) == 1
    assert "pipx install prowler" in capsys.readouterr().err


# ------------------------------------------------------------------ native checks (moto)
def test_spend_alerts(aws):
    acct = aws.client("sts").get_caller_identity()["Account"]
    assert spend_alerts(aws, acct)[0].status == "FAIL"
    aws.client("budgets", region_name="us-east-1").create_budget(
        AccountId=acct,
        Budget={"BudgetName": "m", "BudgetLimit": {"Amount": "10", "Unit": "USD"}, "TimeUnit": "MONTHLY", "BudgetType": "COST"},
        NotificationsWithSubscribers=[{"Notification": {"NotificationType": "ACTUAL", "ComparisonOperator": "GREATER_THAN", "Threshold": 80},
                                       "Subscribers": [{"SubscriptionType": "EMAIL", "Address": "a@example.com"}]}])
    assert spend_alerts(aws, acct)[0].status == "PASS"


def test_ci_oidc(aws):
    iam = aws.client("iam")
    acct = aws.client("sts").get_caller_identity()["Account"]
    assert ci_oidc(aws, acct)[0].status == "MANUAL"
    iam.create_open_id_connect_provider(Url="https://token.actions.githubusercontent.com", ClientIDList=["sts.amazonaws.com"],
                                        ThumbprintList=["f" * 40])
    assert ci_oidc(aws, acct)[0].status == "PASS"
    iam.create_user(UserName="github-deploy")
    iam.create_access_key(UserName="github-deploy")
    iam.create_user(UserName="priya")            # not CI-looking: ignored
    iam.create_access_key(UserName="priya")
    res = ci_oidc(aws, acct)
    assert [r.status for r in res] == ["FAIL"] and "github-deploy" in res[0].message


# ------------------------------------------------------------------ access templates
def test_policy_copies_match_and_deny_data_reads():
    a = (ROOT / "policies" / "security-check-readonly.json").read_text()
    assert a == (ROOT / "billdoctor" / "data" / "security-check-readonly.json").read_text()
    deny = json.loads(a)["Statement"][1]
    assert deny["Effect"] == "Deny" and {"s3:GetObject", "secretsmanager:GetSecretValue", "dynamodb:Scan"} <= set(deny["Action"])


@pytest.mark.parametrize("path", ["client-access/cloudformation-readonly-role.yaml", "client-access/terraform/main.tf"])
def test_role_templates_offer_the_security_check(path):
    text = (ROOT / path).read_text()
    assert "SecurityAudit" in text and "ViewOnlyAccess" in text and "never-read-data" in text


def test_cloudformation_deny_matches_policy_file():
    pol = json.loads((ROOT / "policies" / "security-check-readonly.json").read_text())
    text = (ROOT / "client-access" / "cloudformation-readonly-role.yaml").read_text()
    for action in pol["Statement"][1]["Action"] + pol["Statement"][0]["Action"]:
        assert f"- {action}\n" in text, action

