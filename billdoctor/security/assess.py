"""Turn raw check results into the 25-control assessment, a score and a grade."""
from __future__ import annotations

import datetime as dt
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from .controls import CONTROLS, DPDP_AREAS, SEVERITY_WEIGHT, Control, control_for_check
from .ocsf import CheckResult, cis_refs

# Control statuses
PASS, FAIL, MANUAL, NO_RESOURCES, NOT_EVALUATED = "pass", "fail", "manual", "no-resources", "not-evaluated"
STATUS_LABEL = {PASS: "Pass", FAIL: "Fail", MANUAL: "Review", NO_RESOURCES: "No resources", NOT_EVALUATED: "Not evaluated"}


def grade(score: int) -> str:
    """Same scale as ghaudit (service S2), so both reports read alike."""
    return "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "F"


@dataclass
class ControlResult:
    control: Control
    status: str
    failing: list[CheckResult] = field(default_factory=list)
    passing: int = 0
    manual: list[CheckResult] = field(default_factory=list)
    muted: list[CheckResult] = field(default_factory=list)
    checks_seen: list[str] = field(default_factory=list)
    cis: list[str] = field(default_factory=list)

    @property
    def scored(self) -> bool:
        return self.status in (PASS, FAIL)

    def summary(self) -> str:
        if self.status == FAIL:
            n = len(self.failing)
            return f"{n} failing {'item' if n == 1 else 'items'}" + (f", {self.passing} passing" if self.passing else "")
        if self.status == PASS:
            return f"{self.passing} {'item' if self.passing == 1 else 'items'} checked, all passing"
        if self.status == MANUAL:
            return self.manual[0].message if self.manual else "needs a human review"
        if self.status == NO_RESOURCES:
            return "no matching resources in the scanned regions"
        return "not evaluated (the scanner returned no result - see Method)"

    def to_dict(self) -> dict[str, Any]:
        c = self.control
        return {
            "id": c.id, "group": c.group_name, "title": c.title, "severity": c.severity, "status": self.status,
            "summary": self.summary(), "why": c.why, "prowler_checks": list(c.prowler), "native_check": c.native or None,
            "cis": self.cis, "dpdp_areas": [DPDP_AREAS[a] for a in c.dpdp],
            "fix": {"terraform": c.fix.terraform, "cli": c.fix.cli, "console": c.fix.console},
            "failing": [f.to_dict() for f in self.failing],
            "manual": [f.to_dict() for f in self.manual],
            "muted": [f.to_dict() for f in self.muted],
            "passing_count": self.passing,
        }


@dataclass
class Assessment:
    account_id: str
    account_label: str
    regions: list[str]
    started_at: dt.datetime
    results: list[ControlResult]
    engine: str = "prowler"
    engine_version: str = ""
    profile: str = "baseline"          # or "dpdp" (India technical-safeguards wording)
    synthetic: bool = False
    synthetic_note: str = ""
    errors: list[dict[str, str]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    # -------------------------------------------------------------- scoring
    @property
    def score(self) -> int:
        """Share of the severity weight of evaluated controls that pass, 0-100."""
        total = sum(r.control.weight for r in self.results if r.scored)
        ok = sum(r.control.weight for r in self.results if r.status == PASS)
        return round(100 * ok / total) if total else 0

    @property
    def grade(self) -> str:
        return grade(self.score)

    @property
    def coverage(self) -> int:
        """Share of the total weight that could be evaluated (pass, fail or not applicable)."""
        total = sum(c.weight for c in CONTROLS)
        seen = sum(r.control.weight for r in self.results if r.status in (PASS, FAIL, NO_RESOURCES))
        return round(100 * seen / total)

    def counts(self) -> dict[str, int]:
        c = Counter(r.status for r in self.results)
        return {s: c.get(s, 0) for s in (FAIL, PASS, MANUAL, NO_RESOURCES, NOT_EVALUATED)}

    def failing_by_severity(self) -> dict[str, int]:
        c = Counter(r.control.severity for r in self.results if r.status == FAIL)
        return {s: c.get(s, 0) for s in SEVERITY_WEIGHT}

    def top_risks(self, n: int = 5) -> list[ControlResult]:
        fails = [r for r in self.results if r.status == FAIL]
        return sorted(fails, key=lambda r: (-r.control.weight, -len(r.failing), r.control.id))[:n]

    def by_group(self) -> dict[str, list[ControlResult]]:
        out: dict[str, list[ControlResult]] = {}
        for r in self.results:
            out.setdefault(r.control.group_name, []).append(r)
        return out

    def by_dpdp_area(self) -> dict[str, list[ControlResult]]:
        out: dict[str, list[ControlResult]] = {name: [] for name in DPDP_AREAS.values()}
        for r in self.results:
            for a in r.control.dpdp:
                out[DPDP_AREAS[a]].append(r)
        return out

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": "aws-bill-doctor security baseline check",
            "account_id": self.account_id, "account_label": self.account_label, "regions": self.regions,
            "started_at": self.started_at.isoformat(timespec="seconds"), "engine": self.engine,
            "engine_version": self.engine_version, "profile": self.profile, "synthetic_data": self.synthetic,
            "score": self.score, "grade": self.grade, "coverage_percent": self.coverage,
            "status_counts": self.counts(), "failing_by_severity": self.failing_by_severity(),
            "controls": [r.to_dict() for r in self.results],
            "errors": self.errors, "notes": self.notes,
        }


def assess(check_results: list[CheckResult], *, account_id: str = "", account_label: str = "", regions: list[str] | None = None,
           started_at: dt.datetime | None = None, engine_version: str = "", profile: str = "baseline",
           synthetic: bool = False, errors: list[dict[str, str]] | None = None) -> Assessment:
    to_control = control_for_check()
    refs = cis_refs(check_results)
    buckets: dict[str, list[CheckResult]] = {c.id: [] for c in CONTROLS}
    for r in check_results:
        cid = _native_control(r.check_id) or to_control.get(r.check_id)
        if cid:
            buckets[cid].append(r)
    results = []
    for c in CONTROLS:
        rs = buckets[c.id]
        cr = ControlResult(control=c, status=NOT_EVALUATED)
        cr.muted = [r for r in rs if r.muted]
        live = [r for r in rs if not r.muted]
        cr.failing = [r for r in live if r.status == "FAIL"]
        cr.manual = [r for r in live if r.status == "MANUAL"]
        cr.passing = sum(1 for r in live if r.status == "PASS")
        cr.checks_seen = sorted({r.check_id for r in rs})
        cr.cis = sorted({ref for p in c.prowler for ref in refs.get(p, [])})
        if cr.failing:
            cr.status = FAIL
        elif cr.passing:
            cr.status = PASS
        elif cr.manual:
            cr.status = MANUAL
        elif cr.muted:
            cr.status = PASS            # every finding was accepted as a known risk; listed in the report
        elif c.scope == "resource" and not _errored(c, errors or []):
            cr.status = NO_RESOURCES
        results.append(cr)
    if not account_id:
        account_id = next((r.account_id for r in check_results if r.account_id), "unknown")
    if not engine_version:
        engine_version = next((r.prowler_version for r in check_results if r.prowler_version), "")
    found_regions = sorted({r.region for r in check_results if r.region and r.region != "global"})
    return Assessment(account_id=account_id, account_label=account_label, regions=regions or found_regions,
                      started_at=started_at or dt.datetime.now(dt.timezone.utc), results=results,
                      engine_version=engine_version, profile=profile, synthetic=synthetic, errors=list(errors or []))


def _native_control(check_id: str) -> str | None:
    if not check_id.startswith("native:"):
        return None
    name = check_id.split(":", 1)[1]
    return next((c.id for c in CONTROLS if c.native == name), None)


def _errored(c: Control, errors: list[dict[str, str]]) -> bool:
    names = set(c.prowler) | ({f"native:{c.native}"} if c.native else set())
    return any(e.get("check") in names for e in errors)


def compare(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    """Retest view from two findings.json files: what got fixed, what is still open, what is new."""
    b = {c["id"]: c for c in before.get("controls", [])}
    a = {c["id"]: c for c in after.get("controls", [])}
    fixed = [cid for cid in a if b.get(cid, {}).get("status") == FAIL and a[cid]["status"] == PASS]
    still = [cid for cid in a if b.get(cid, {}).get("status") == FAIL and a[cid]["status"] == FAIL]
    new = [cid for cid in a if b.get(cid, {}).get("status") != FAIL and a[cid]["status"] == FAIL]
    return {"before_score": before.get("score"), "after_score": after.get("score"),
            "before_grade": before.get("grade"), "after_grade": after.get("grade"),
            "fixed": fixed, "still_failing": still, "new_failures": new,
            "titles": {cid: a[cid]["title"] for cid in a}}
