"""Run checks across regions and collect the results."""
from __future__ import annotations

import datetime as dt
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from . import checks  # noqa: F401  (registers checks)
from .models import REGISTRY, Finding, ScanContext
from .pricing import PRICES_AS_OF, Prices


@dataclass
class ScanResult:
    account_id: str
    account_label: str
    regions: list[str]
    started_at: dt.datetime
    finished_at: dt.datetime | None = None
    findings: list[Finding] = field(default_factory=list)
    errors: list[dict[str, str]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    cost_by_service: list[dict[str, Any]] = field(default_factory=list)
    synthetic: bool = False
    prices_as_of: str = PRICES_AS_OF
    lookback_days: int = 14
    checks_run: list[str] = field(default_factory=list)

    @property
    def clean_checks(self) -> list[str]:
        """Checks that ran everywhere without error and found nothing."""
        failed = {e["check"] for e in self.errors}
        found = {f.check_id for f in self.findings}
        return [c for c in self.checks_run if c not in found and c not in failed]

    @property
    def monthly_savings(self) -> float:
        """Sum of the best saving per resource (an idle t2 instance is not counted
        both as 'stop it' and as 'upgrade it')."""
        best: dict[tuple[str, str], float] = {}
        for f in self.findings:
            key = (f.region, f.resource_id)
            best[key] = max(best.get(key, 0.0), f.est_monthly_savings or 0.0)
        return round(sum(best.values()), 2)

    @property
    def quick_wins(self) -> list[Finding]:
        return sorted([f for f in self.findings if f.fix_risk == "low" and (f.est_monthly_savings or 0) > 0],
                      key=lambda f: -(f.est_monthly_savings or 0))

    def by_check(self) -> dict[str, list[Finding]]:
        out: dict[str, list[Finding]] = defaultdict(list)
        for f in sorted(self.findings, key=lambda f: -(f.est_monthly_savings or 0)):
            out[f.check_id].append(f)
        return dict(sorted(out.items()))

    def priority_counts(self) -> dict[str, int]:
        c = Counter(f.priority for f in self.findings)
        return {k: c.get(k, 0) for k in ("high", "medium", "low", "info")}

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": "aws-bill-doctor",
            "account_id": self.account_id,
            "account_label": self.account_label,
            "regions": self.regions,
            "started_at": self.started_at.isoformat(timespec="seconds"),
            "finished_at": self.finished_at.isoformat(timespec="seconds") if self.finished_at else None,
            "synthetic_data": self.synthetic,
            "prices_as_of": self.prices_as_of,
            "checks_run": self.checks_run,
            "estimated_monthly_savings_usd": self.monthly_savings,
            "estimated_annual_savings_usd": round(self.monthly_savings * 12, 2),
            "priority_counts": self.priority_counts(),
            "findings": [f.to_dict() for f in self.findings],
            "errors": self.errors,
            "notes": self.notes,
            "cost_by_service": self.cost_by_service,
        }


def account_id(session: Any) -> str:
    try:
        return session.client("sts").get_caller_identity()["Account"]
    except (ClientError, BotoCoreError):
        return "unknown"


def run_scan(session: Any, regions: list[str], only: list[str] | None = None, account_label: str = "",
             now: dt.datetime | None = None, synthetic: bool = False, **ctx_kwargs: Any) -> ScanResult:
    prices = Prices()
    result = ScanResult(account_id=account_id(session), account_label=account_label, regions=regions,
                        started_at=now or dt.datetime.now(dt.timezone.utc), synthetic=synthetic,
                        lookback_days=ctx_kwargs.get("lookback_days", 14))
    selected = [c for cid, c in sorted(REGISTRY.items()) if not only or cid in only]
    result.checks_run = [c.id for c in selected]
    for region in regions:
        ctx = ScanContext(session, region, prices, now=now, **ctx_kwargs)
        for info in selected:
            try:
                result.findings.extend(info.func(ctx))
            except ClientError as e:
                code = e.response.get("Error", {}).get("Code", "ClientError")
                result.errors.append({"check": info.id, "region": region, "error": f"{code}: {e.response.get('Error', {}).get('Message', '')}"[:300]})
            except BotoCoreError as e:
                result.errors.append({"check": info.id, "region": region, "error": str(e)[:300]})
        for n in ctx.notes:
            if n not in result.notes:
                result.notes.append(n)
    result.finished_at = dt.datetime.now(dt.timezone.utc)
    return result


def cost_by_service(session: Any, now: dt.datetime | None = None, months: int = 3) -> list[dict[str, Any]]:
    """Spend per service for the last full months + month to date. Each call costs $0.01."""
    now = now or dt.datetime.now(dt.timezone.utc)
    first = now.date().replace(day=1)
    start = first
    for _ in range(months):
        start = (start - dt.timedelta(days=1)).replace(day=1)
    end = now.date() + dt.timedelta(days=1)
    ce = session.client("ce", region_name="us-east-1")
    resp = ce.get_cost_and_usage(
        TimePeriod={"Start": start.isoformat(), "End": end.isoformat()},
        Granularity="MONTHLY", Metrics=["UnblendedCost"],
        GroupBy=[{"Type": "DIMENSION", "Key": "SERVICE"}],
    )
    table: dict[str, dict[str, float]] = defaultdict(dict)
    periods = []
    for r in resp.get("ResultsByTime", []):
        p = r["TimePeriod"]["Start"][:7]
        periods.append(p)
        for g in r.get("Groups", []):
            table[g["Keys"][0]][p] = round(float(g["Metrics"]["UnblendedCost"]["Amount"]), 2)
    rows = [{"service": s, **{p: v.get(p, 0.0) for p in periods}} for s, v in table.items()]
    rows.sort(key=lambda r: -sum(r[p] for p in periods))
    return rows[:12]
