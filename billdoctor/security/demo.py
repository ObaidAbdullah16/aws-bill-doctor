"""`billdoctor security demo`: sample reports from real Prowler checks run against a simulated account.

The results live in `billdoctor/data/security-demo*.json` (rebuilt by scripts/make_security_demo_fixture.py),
so the demo needs neither AWS nor Prowler. "before" is a fictional company's typical state; "after" is the
same account once the fix pack is applied, which gives the retest report.
"""
from __future__ import annotations

import datetime as dt
import json
from importlib import resources

from .assess import NOT_EVALUATED, Assessment, assess
from .ocsf import CheckResult, parse_item

SIMULATOR_NOTE = ("real Prowler checks run against a simulated AWS account (moto) seeded with a fictional company's "
                  "typical mistakes. No customer data.")
FILES = {"before": "data/security-demo.json", "after": "data/security-demo-after.json"}


def load_demo(stage: str = "before") -> tuple[list[CheckResult], dict]:
    data = json.loads(resources.files("billdoctor").joinpath(FILES[stage]).read_text(encoding="utf-8"))
    results = [cr for cr in (parse_item(it) for it in data["prowler"]) if cr]
    results += [CheckResult(**n) for n in data["native"]]
    return results, data


def run_demo(profile: str = "baseline", stage: str = "before", now: dt.datetime | None = None) -> Assessment:
    results, data = load_demo(stage)
    a = assess(results, account_label=data.get("account_label", "Demo account"), regions=data.get("regions"),
               started_at=now, profile=profile, synthetic=True)
    a.synthetic_note = SIMULATOR_NOTE
    missing = [r.control.id for r in a.results if r.status == NOT_EVALUATED]
    if missing:
        a.notes.append(f"Not evaluated in the simulator ({', '.join(missing)}): it has no root user, IAM Access Analyzer or "
                       "account-level S3 settings. A scan of a real account evaluates them.")
    if stage == "after":
        a.notes.append("Retest after the fix pack. AWS Config (LD-03) is still off: this fictional client chose to add it next quarter.")
    return a
