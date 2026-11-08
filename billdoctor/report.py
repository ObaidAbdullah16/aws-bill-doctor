"""Render a ScanResult as HTML, Markdown, JSON or CSV."""
from __future__ import annotations

import csv
import io
import json
from pathlib import Path

from jinja2 import Environment, PackageLoader, select_autoescape

from . import __version__
from .models import REGISTRY
from .scanner import ScanResult


def _env() -> Environment:
    env = Environment(loader=PackageLoader("billdoctor", "templates"), autoescape=select_autoescape(["html", "j2"]),
                      trim_blocks=True, lstrip_blocks=True)
    env.filters["usd"] = lambda v: "-" if v is None else f"${v:,.2f}"
    return env


def to_html(r: ScanResult) -> str:
    return _env().get_template("report.html.j2").render(r=r, checks=REGISTRY, version=__version__)


def to_json(r: ScanResult) -> str:
    return json.dumps(r.to_dict(), indent=2, default=str)


def to_csv(r: ScanResult) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["priority", "check_id", "title", "region", "resource_type", "resource_id", "detail",
                "monthly_cost_usd", "est_monthly_savings_usd", "fix_risk", "recommendation", "fix_command"])
    for f in sorted(r.findings, key=lambda f: -(f.est_monthly_savings or 0)):
        w.writerow([f.priority, f.check_id, f.title, f.region, f.resource_type, f.resource_id, f.detail,
                    f.monthly_cost, f.est_monthly_savings, f.fix_risk, f.recommendation, f.fix_command])
    return buf.getvalue()


def to_markdown(r: ScanResult) -> str:
    lines = [f"# AWS Bill Doctor report - account {r.account_label or r.account_id}", ""]
    if r.synthetic:
        lines += ["> **SYNTHETIC DEMO DATA.** Generated against a simulated AWS account; no real customer data.", ""]
    lines += [
        f"- Regions: {', '.join(r.regions)}",
        f"- Scanned: {r.started_at:%Y-%m-%d %H:%M UTC}",
        f"- **Estimated savings: ${r.monthly_savings:,.2f}/month (${r.monthly_savings * 12:,.2f}/year)**",
        f"- Findings: {len(r.findings)} ({', '.join(f'{k} {v}' for k, v in r.priority_counts().items() if v)})",
        "",
        "## Top findings",
        "",
        "| Priority | Check | Resource | Region | Saving / month | Detail |",
        "|---|---|---|---|---|---|",
    ]
    top = sorted(r.findings, key=lambda f: -(f.est_monthly_savings or 0))[:15]
    for f in top:
        s = "-" if f.est_monthly_savings is None else f"${f.est_monthly_savings:,.2f}"
        lines.append(f"| {f.priority} | {f.check_id} | `{f.resource_id}` | {f.region} | {s} | {f.detail} |")
    lines += ["", "## Quick wins (low-risk fixes)", ""]
    for f in r.quick_wins[:10]:
        lines.append(f"- **{f.check_id}** `{f.resource_id}`: {f.recommendation}  \n  `{f.fix_command}`")
    if not r.quick_wins:
        lines.append("None found.")
    if r.errors:
        lines += ["", "## Checks that could not run", ""]
        lines += [f"- {e['check']} in {e['region']}: {e['error']}" for e in r.errors]
    lines += ["", "## Method", "",
              f"Read-only API calls; prices are approximate on-demand list prices ({r.prices_as_of}). "
              "Savings are estimates - confirm with the resource owner and snapshot before deleting anything."]
    for n in r.notes:
        lines.append(f"- Note: {n}")
    return "\n".join(lines) + "\n"


def write_all(r: ScanResult, out_dir: str) -> list[Path]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    files = {
        "report.html": to_html(r),
        "report.md": to_markdown(r),
        "findings.json": to_json(r),
        "findings.csv": to_csv(r),
    }
    written = []
    for name, text in files.items():
        p = out / name
        p.write_text(text, encoding="utf-8")
        written.append(p)
    return written
