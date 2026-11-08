"""Findings, the check registry and the scan context shared by all checks."""
from __future__ import annotations

import datetime as dt
from collections.abc import Callable, Iterable
from dataclasses import asdict, dataclass, field
from typing import Any

from .pricing import Prices

HOURS_PER_MONTH = 730


@dataclass
class Finding:
    check_id: str
    title: str
    region: str
    resource_type: str
    resource_id: str
    detail: str
    recommendation: str
    monthly_cost: float | None = None          # what the resource costs now (USD/month)
    est_monthly_savings: float | None = None   # what the fix saves (USD/month), None = not quantifiable
    fix_command: str | None = None             # a command to review and run - never executed by this tool
    fix_risk: str = "low"                      # risk of applying the fix: low | medium | high
    tags: dict[str, str] = field(default_factory=dict)

    @property
    def priority(self) -> str:
        s = self.est_monthly_savings
        if s is None:
            return "info"
        if s >= 50:
            return "high"
        if s >= 10:
            return "medium"
        return "low"

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["priority"] = self.priority
        return d


@dataclass(frozen=True)
class CheckInfo:
    id: str
    title: str
    service: str
    why: str
    func: Callable[[ScanContext], Iterable[Finding]]


REGISTRY: dict[str, CheckInfo] = {}


def check(id: str, title: str, service: str, why: str):
    """Decorator that registers a check function."""
    def wrap(fn: Callable[[ScanContext], Iterable[Finding]]):
        REGISTRY[id] = CheckInfo(id, title, service, why, fn)
        return fn
    return wrap


class ScanContext:
    """One region of one account. Caches boto3 clients and offers small helpers."""

    def __init__(self, session: Any, region: str, prices: Prices, now: dt.datetime | None = None,
                 lookback_days: int = 14, snapshot_age_days: int = 90, stopped_days: int = 30):
        self.session = session
        self.region = region
        self.prices = prices
        self.now = now or dt.datetime.now(dt.timezone.utc)
        self.lookback_days = lookback_days
        self.snapshot_age_days = snapshot_age_days
        self.stopped_days = stopped_days
        self._clients: dict[str, Any] = {}
        self.notes: list[str] = []

    def client(self, name: str) -> Any:
        if name not in self._clients:
            self._clients[name] = self.session.client(name, region_name=self.region)
        return self._clients[name]

    def paginate(self, service: str, op: str, key: str, **kwargs: Any) -> list[Any]:
        out: list[Any] = []
        for page in self.client(service).get_paginator(op).paginate(**kwargs):
            out.extend(page.get(key, []))
        return out

    def metric(self, namespace: str, name: str, dims: dict[str, str], stat: str) -> list[float]:
        """Daily datapoints over the lookback window for one statistic."""
        resp = self.client("cloudwatch").get_metric_statistics(
            Namespace=namespace,
            MetricName=name,
            Dimensions=[{"Name": k, "Value": v} for k, v in dims.items()],
            StartTime=self.now - dt.timedelta(days=self.lookback_days),
            EndTime=self.now,
            Period=86400,
            Statistics=[stat],
        )
        return [p[stat] for p in resp.get("Datapoints", [])]

    def volume_cost(self, v: dict[str, Any]) -> float | None:
        """Monthly cost of an EBS volume: storage plus provisioned performance. Without the IOPS part
        an unattached io1 volume with 3,000 IOPS would look ~15 times cheaper than it is."""
        vtype, size = v["VolumeType"], v["Size"]
        gb = self.money("ebs_gb_month", vtype)
        if gb is None:
            return None
        cost = size * gb
        iops, throughput = v.get("Iops") or 0, v.get("Throughput") or 0
        if vtype in ("io1", "io2") and iops:
            per_iops = self.money("ebs_iops_month", vtype)
            if per_iops is None:
                return None
            if vtype == "io2":  # tiered per volume: first 32,000 IOPS full price, next 32,000 at 70%, the rest at 49%
                iops = min(iops, 32000) + 0.7 * min(max(iops - 32000, 0), 32000) + 0.49 * max(iops - 64000, 0)
            cost += iops * per_iops
        elif vtype == "gp3":
            extra_iops, extra_throughput = max(iops - 3000, 0), max(throughput - 125, 0)
            if extra_iops or extra_throughput:
                per_iops, per_mibps = self.money("ebs_iops_month", "gp3"), self.money("ebs_throughput_month", "gp3")
                if per_iops is None or per_mibps is None:
                    return None
                cost += extra_iops * per_iops + extra_throughput * per_mibps
        return round(cost, 2)

    def money(self, key: str, *sub: str) -> float | None:
        value, fallback = self.prices.get(self.region, key, *sub)
        if fallback and value is not None:
            note = f"{self.region}: no local price for {key}{'/' + '/'.join(sub) if sub else ''}; used us-east-1 as an approximation"
            if note not in self.notes:
                self.notes.append(note)
        return value
