"""Render an Assessment as HTML, Markdown, JSON and CSV (same file set as the cost report)."""
from __future__ import annotations

import csv
import io
import json
from pathlib import Path
from typing import Any

from .. import __version__
from ..report import _env
from .assess import FAIL, STATUS_LABEL, Assessment
from .controls import prowler_checks

TITLES = {"baseline": "AWS security baseline check", "dpdp": "DPDP technical safeguards check"}


def title(a: Assessment) -> str:
    return TITLES.get(a.profile, TITLES["baseline"])


def to_html(a: Assessment, retest: dict[str, Any] | None = None) -> str:
    return _env().get_template("security.html.j2").render(
        a=a, title=title(a), dpdp=a.profile == "dpdp", labels=STATUS_LABEL, retest=retest,
        nchecks=len(prowler_checks()), version=__version__)


def to_json(a: Assessment) -> str:
    return json.dumps(a.to_dict(), indent=2, default=str)


def to_csv(a: Assessment) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["control_id", "control", "severity", "control_status", "check_id", "finding_status", "region",
                "resource", "resource_type", "finding", "fix_terraform", "fix_cli", "fix_console"])
    for r in a.results:
        c = r.control
        rows = r.failing + r.manual or [None]
        for f in rows:
            w.writerow([c.id, c.title, c.severity, r.status,
                        f.check_id if f else "", f.status if f else "", f.region if f else "",
                        (f.resource_uid or f.resource_name) if f else "", f.resource_type if f else "",
                        f.message if f else r.summary(), c.fix.terraform, c.fix.cli, c.fix.console])
    return buf.getvalue()


def to_markdown(a: Assessment) -> str:
    lines = [f"# {title(a)} - account {a.account_label or a.account_id}", ""]
    if a.synthetic:
        lines += [f"> **SYNTHETIC DEMO DATA.** {a.synthetic_note or 'Generated against a simulated AWS account; no customer data.'}", ""]
    if a.profile == "dpdp":
        lines += ["> Technical readiness review against India's DPDP Rules - **not legal advice**.", ""]
    c = a.counts()
    lines += [
        f"- Regions: {', '.join(a.regions) or '-'}",
        f"- Scanned: {a.started_at:%Y-%m-%d %H:%M UTC}",
        f"- **Score: {a.score}/100 (grade {a.grade})** - coverage {a.coverage}%",
        f"- Controls: {c[FAIL]} failing, {c['pass']} passing, {c['no-resources']} not applicable, {c['manual']} to review, {c['not-evaluated']} not evaluated",
        "",
        "## Top risks",
        "",
        "| Severity | Control | Finding | First step |",
        "|---|---|---|---|",
    ]
    for r in a.top_risks(5):
        f = r.failing[0]
        step = (r.control.fix.terraform or r.control.fix.cli or r.control.fix.console).split("\n")[0]
        more = f" (+{len(r.failing) - 1} more)" if len(r.failing) > 1 else ""
        lines.append(f"| {r.control.severity} | **{r.control.id}** {r.control.title} | {f.message}{more} | `{step}` |")
    if not a.top_risks(1):
        lines.append("| - | No failing controls | | |")
    lines += ["", "## All controls", "", "| Status | ID | Control | Severity | Result |", "|---|---|---|---|---|"]
    for r in a.results:
        lines.append(f"| {STATUS_LABEL[r.status]} | {r.control.id} | {r.control.title} | {r.control.severity} | {r.summary()} |")
    if a.errors:
        lines += ["", "## Checks that could not run", ""] + [f"- {e['check']} in {e['region']}: {e['error']}" for e in a.errors]
    lines += ["", "## Method", "",
              "Read-only role (SecurityAudit + ViewOnlyAccess, explicit deny on data reads); "
              f"engine {('Prowler ' + a.engine_version) if a.engine_version else a.engine}; every finding reviewed by a person. "
              "Findings reflect the configuration at scan time; this is not a penetration test or a guarantee."]
    lines += [f"- Note: {n}" for n in a.notes]
    return "\n".join(lines) + "\n"


def write_all(a: Assessment, out_dir: str, retest: dict[str, Any] | None = None) -> list[Path]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    files = {"report.html": to_html(a, retest), "report.md": to_markdown(a), "findings.json": to_json(a), "findings.csv": to_csv(a)}
    written = []
    for name, text in files.items():
        p = out / name
        p.write_text(text, encoding="utf-8")
        written.append(p)
    return written
