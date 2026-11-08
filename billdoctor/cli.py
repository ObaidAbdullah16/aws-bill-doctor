"""billdoctor command line.

    billdoctor scan --profile client-audit --regions ap-south-1,us-east-1 --out report/
    billdoctor scan --role-arn arn:aws:iam::111122223333:role/BillDoctorReadOnly --external-id <id>
    billdoctor demo --out sample-report/      # synthetic account, no AWS needed
    billdoctor checks                         # list the checks
    billdoctor policy                         # print the read-only IAM policy

    billdoctor security scan --role-arn <arn> --external-id <id> --regions all --out audits/acme/security   # S8 (needs Prowler)
    billdoctor security report --prowler-json prowler.ocsf.json --out report/   # convert an existing Prowler run
    billdoctor security demo --out sample-security-report/                       # simulated account, no AWS needed
    billdoctor health-check --role-arn <arn> --external-id <id> --out audits/acme  # cost + security bundle
"""
from __future__ import annotations

import argparse
import sys
from importlib import resources

from . import __version__
from .models import REGISTRY


def _session(args: argparse.Namespace):
    import boto3

    base = boto3.Session(profile_name=args.profile) if args.profile else boto3.Session()
    if not args.role_arn:
        return base
    params = {"RoleArn": args.role_arn, "RoleSessionName": "billdoctor-audit", "DurationSeconds": 3600}
    if args.external_id:
        params["ExternalId"] = args.external_id
    creds = base.client("sts").assume_role(**params)["Credentials"]
    return boto3.Session(aws_access_key_id=creds["AccessKeyId"], aws_secret_access_key=creds["SecretAccessKey"],
                         aws_session_token=creds["SessionToken"], region_name=base.region_name)


def _regions(session, value: str | None) -> list[str]:
    if value == "all":
        ec2 = session.client("ec2", region_name=session.region_name or "us-east-1")
        return sorted(r["RegionName"] for r in ec2.describe_regions(
            Filters=[{"Name": "opt-in-status", "Values": ["opt-in-not-required", "opted-in"]}])["Regions"])
    if value:
        return [r.strip() for r in value.split(",") if r.strip()]
    return [session.region_name or "ap-southeast-2"]


def cmd_scan(args: argparse.Namespace) -> int:
    from .report import write_all
    from .scanner import cost_by_service, run_scan

    only = [c.strip().upper() for c in args.checks.split(",") if c.strip()] if args.checks else None
    unknown = sorted(set(only or []) - set(REGISTRY))
    if unknown:
        print(f"Unknown check ID(s): {', '.join(unknown)}. Run 'billdoctor checks' to list them.", file=sys.stderr)
        return 2
    session = _session(args)
    regions = _regions(session, args.regions)
    print(f"Scanning {', '.join(regions)} with {len(only or REGISTRY)} checks (read-only)...", file=sys.stderr)
    result = run_scan(session, regions, only=only, account_label=args.label or "",
                      lookback_days=args.lookback_days, snapshot_age_days=args.snapshot_age_days,
                      stopped_days=args.stopped_days)
    if args.cost_explorer:
        try:
            result.cost_by_service = cost_by_service(session)
        except Exception as e:  # noqa: BLE001
            result.errors.append({"check": "cost-explorer", "region": "global", "error": str(e)[:300]})
    files = write_all(result, args.out)
    print(f"Estimated savings: ${result.monthly_savings:,.2f}/month across {len(result.findings)} findings")
    for f in files:
        print(f"  wrote {f}")
    if result.errors:
        print(f"  {len(result.errors)} check(s) could not run - see the report", file=sys.stderr)
    return 0


def cmd_demo(args: argparse.Namespace) -> int:
    try:
        from .demo import run_demo
        result, files = run_demo(args.out)
    except ImportError:
        print("The demo needs moto: pip install 'aws-bill-doctor[demo]'", file=sys.stderr)
        return 1
    print(f"SYNTHETIC demo: ${result.monthly_savings:,.2f}/month across {len(result.findings)} findings")
    for f in files:
        print(f"  wrote {f}")
    return 0


def cmd_checks(_: argparse.Namespace) -> int:
    for cid, c in sorted(REGISTRY.items()):
        print(f"{cid:9} {c.service:11} {c.title}")
    return 0


def cmd_policy(_: argparse.Namespace) -> int:
    print(resources.files("billdoctor").joinpath("data/billdoctor-readonly.json").read_text(encoding="utf-8"))
    return 0


# ---------------------------------------------------------------- security baseline (service S8)
def _load_previous(path: str | None) -> dict | None:
    if not path:
        return None
    import json
    from pathlib import Path
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _security_assessment(args: argparse.Namespace, prowler_json: str | None = None):
    """Run Prowler (or read its output), add the native checks, and assess."""
    import tempfile
    from pathlib import Path

    from .scanner import account_id as get_account_id
    from .security import prowler as prowler_runner
    from .security.assess import assess
    from .security.controls import CONTROLS
    from .security.extras import run_native
    from .security.ocsf import load

    session = _session(args) if (prowler_json is None or args.native) else None
    regions = None
    if session is not None and args.regions and args.regions != "all":
        regions = _regions(session, args.regions)
    elif prowler_json is None and args.regions and args.regions != "all":
        regions = [r.strip() for r in args.regions.split(",") if r.strip()]
    if prowler_json is None:
        raw_dir = Path(args.out) / "raw" if args.keep_raw else Path(tempfile.mkdtemp(prefix="s8-"))
        raw = prowler_runner.run(raw_dir, regions=regions, profile=args.profile, role_arn=args.role_arn, external_id=args.external_id)
        results = load(raw)
        if not args.keep_raw:
            import shutil
            shutil.rmtree(raw_dir, ignore_errors=True)   # raw scanner output is not kept unless asked (data-handling rule)
    else:
        results = load(prowler_json)
    errors: list[dict[str, str]] = []
    acct = next((r.account_id for r in results if r.account_id), "")
    if session is not None:
        acct = acct or get_account_id(session)
        native, errors = run_native(session, acct, [c.native for c in CONTROLS if c.native])
        results += native
    a = assess(results, account_id=acct, account_label=args.label or "", regions=regions,
               profile="dpdp" if args.dpdp else "baseline", errors=errors)
    if session is None:
        a.notes.append("Native checks (spend alerts, CI/CD credentials) were not run: re-run with --native and AWS access to include them.")
    if getattr(args, "banner", None):
        a.synthetic, a.synthetic_note = True, args.banner
    return a


def _write_security(a, args: argparse.Namespace) -> int:
    from .security.assess import compare
    from .security.report import write_all

    prev = _load_previous(args.previous)
    retest = compare(prev, a.to_dict()) if prev else None
    files = write_all(a, args.out, retest)
    print(f"Security baseline: {a.score}/100 (grade {a.grade}), {a.counts()['fail']} of {len(a.results)} controls failing, coverage {a.coverage}%")
    if retest:
        print(f"Retest: {retest['before_score']} -> {retest['after_score']} ({len(retest['fixed'])} fixed, {len(retest['still_failing'])} still failing)")
    for f in files:
        print(f"  wrote {f}")
    return 0


def cmd_security_scan(args: argparse.Namespace) -> int:
    try:
        a = _security_assessment(args)
    except FileNotFoundError as e:
        print(str(e), file=sys.stderr)
        return 1
    return _write_security(a, args)


def cmd_security_report(args: argparse.Namespace) -> int:
    return _write_security(_security_assessment(args, prowler_json=args.prowler_json), args)


def cmd_security_demo(args: argparse.Namespace) -> int:
    from pathlib import Path

    from .security.assess import compare
    from .security.demo import run_demo
    from .security.report import write_all

    profile = "dpdp" if args.dpdp else "baseline"
    before = run_demo(profile, "before")
    after = run_demo(profile, "after")
    files = write_all(before, args.out) + write_all(after, str(Path(args.out) / "retest"), compare(before.to_dict(), after.to_dict()))
    print(f"SYNTHETIC demo: {before.score}/100 ({before.grade}) before, {after.score}/100 ({after.grade}) after the fix pack")
    for f in files:
        print(f"  wrote {f}")
    return 0


def cmd_security_controls(_: argparse.Namespace) -> int:
    from .security.controls import CONTROLS

    for c in CONTROLS:
        src = ", ".join(c.prowler) if c.prowler else f"native:{c.native}"
        print(f"{c.id}  {c.severity:8} {c.title}\n        {src}")
    return 0


def cmd_security_policy(_: argparse.Namespace) -> int:
    print(resources.files("billdoctor").joinpath("data/security-check-readonly.json").read_text(encoding="utf-8"))
    return 0


def cmd_security_compare(args: argparse.Namespace) -> int:
    from .security.assess import compare

    r = compare(_load_previous(args.before), _load_previous(args.after))
    print(f"score {r['before_score']} ({r['before_grade']}) -> {r['after_score']} ({r['after_grade']})")
    for key, label in (("fixed", "fixed"), ("still_failing", "still failing"), ("new_failures", "new")):
        for cid in r[key]:
            print(f"  {label:13} {cid} {r['titles'][cid]}")
    return 0


def cmd_health_check(args: argparse.Namespace) -> int:
    from .security.healthcheck import write_bundle

    if args.demo:
        try:
            from .demo import run_demo as run_cost_demo
            cost, _ = run_cost_demo(str(__import__("tempfile").mkdtemp(prefix="hc-")))
        except ImportError:
            print("The demo needs moto: pip install 'aws-bill-doctor[demo]'", file=sys.stderr)
            return 1
        from .security.demo import run_demo
        sec = run_demo("dpdp" if args.dpdp else "baseline")
    else:
        from .scanner import run_scan
        session = _session(args)
        regions = _regions(session, args.regions)
        cost = run_scan(session, regions, account_label=args.label or "")
        try:
            args.native, args.keep_raw, args.previous = True, False, None
            sec = _security_assessment(args)
        except FileNotFoundError as e:
            print(str(e), file=sys.stderr)
            return 1
    files = write_bundle(cost, sec, args.out)
    print(f"Health check: ${cost.monthly_savings:,.2f}/month savings, security {sec.score}/100 ({sec.grade})")
    for f in files:
        print(f"  wrote {f}")
    return 0


def _add_access_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--profile", help="AWS CLI profile")
    p.add_argument("--role-arn", help="cross-account read-only role to assume (client accounts)")
    p.add_argument("--external-id", help="external ID required by the client's role")
    p.add_argument("--regions", help="comma-separated regions, or 'all' (default: all for security, profile region for cost)")
    p.add_argument("--label", help="account name shown in the report")


def main(argv: list[str] | None = None) -> int:
    from . import checks  # noqa: F401  (register checks)

    ap = argparse.ArgumentParser(prog="billdoctor", description="Find AWS waste with read-only access.")
    ap.add_argument("--version", action="version", version=f"billdoctor {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="scan an AWS account (read-only)")
    s.add_argument("--profile", help="AWS CLI profile")
    s.add_argument("--role-arn", help="cross-account read-only role to assume (client accounts)")
    s.add_argument("--external-id", help="external ID required by the client's role")
    s.add_argument("--regions", help="comma-separated regions, or 'all' (default: profile region)")
    s.add_argument("--checks", help="only these check IDs, comma-separated")
    s.add_argument("--label", help="account name shown in the report")
    s.add_argument("--out", default="billdoctor-report", help="output folder")
    s.add_argument("--cost-explorer", action="store_true", help="add spend-by-service table (Cost Explorer API: $0.01 per call)")
    s.add_argument("--lookback-days", type=int, default=14)
    s.add_argument("--snapshot-age-days", type=int, default=90)
    s.add_argument("--stopped-days", type=int, default=30)
    s.set_defaults(func=cmd_scan)

    d = sub.add_parser("demo", help="generate a report from a synthetic account (no AWS needed)")
    d.add_argument("--out", default="sample-report")
    d.set_defaults(func=cmd_demo)

    sub.add_parser("checks", help="list checks").set_defaults(func=cmd_checks)
    sub.add_parser("policy", help="print the read-only IAM policy").set_defaults(func=cmd_policy)

    sec = sub.add_parser("security", help="AWS security baseline check (service S8): 25 controls, read-only").add_subparsers(dest="sec", required=True)
    ss = sec.add_parser("scan", help="run Prowler with the curated checks, add native checks, write the report")
    _add_access_args(ss)
    ss.add_argument("--out", default="security-report")
    ss.add_argument("--dpdp", action="store_true", help="India variant: DPDP technical-safeguards wording and view")
    ss.add_argument("--previous", help="findings.json of an earlier scan: adds a retest section")
    ss.add_argument("--keep-raw", action="store_true", help="keep Prowler's raw output in OUT/raw (deleted by default)")
    ss.add_argument("--banner", help="label the report as a demo, e.g. for a deliberately misconfigured sandbox account")
    ss.set_defaults(func=cmd_security_scan, native=True)
    sr = sec.add_parser("report", help="build the report from an existing Prowler JSON-OCSF file")
    sr.add_argument("--prowler-json", required=True)
    _add_access_args(sr)
    sr.add_argument("--native", action="store_true", help="also run the two native checks (needs AWS access)")
    sr.add_argument("--out", default="security-report")
    sr.add_argument("--dpdp", action="store_true")
    sr.add_argument("--previous")
    sr.add_argument("--banner")
    sr.set_defaults(func=cmd_security_report, keep_raw=False)
    sd = sec.add_parser("demo", help="sample before/after reports from a simulated account (no AWS needed)")
    sd.add_argument("--out", default="sample-security-report")
    sd.add_argument("--dpdp", action="store_true")
    sd.set_defaults(func=cmd_security_demo)
    sec.add_parser("controls", help="list the 25 controls and the checks behind them").set_defaults(func=cmd_security_controls)
    sec.add_parser("policy", help="print the extra read-only policy (and the deny on data reads)").set_defaults(func=cmd_security_policy)
    sc = sec.add_parser("compare", help="retest summary from two findings.json files")
    sc.add_argument("--before", required=True)
    sc.add_argument("--after", required=True)
    sc.set_defaults(func=cmd_security_compare)

    h = sub.add_parser("health-check", help="AWS Health Check bundle: cost (S1) + security (S8), one summary page")
    _add_access_args(h)
    h.add_argument("--out", default="health-check")
    h.add_argument("--dpdp", action="store_true")
    h.add_argument("--demo", action="store_true", help="synthetic accounts, no AWS needed (needs the [demo] extra)")
    h.set_defaults(func=cmd_health_check)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
