"""Read Prowler's JSON-OCSF output (`prowler aws -M json-ocsf`).

Only the fields the report needs are kept. Unknown or malformed entries are skipped, not fatal:
a client report must not die because one finding has an unexpected shape.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class CheckResult:
    check_id: str                 # Prowler check, e.g. iam_root_mfa_enabled
    status: str                   # PASS | FAIL | MANUAL
    region: str
    resource_uid: str
    resource_type: str
    resource_name: str
    message: str
    severity: str = ""            # Prowler's own severity (informational; the baseline uses its own)
    muted: bool = False
    compliance: dict[str, list[str]] = field(default_factory=dict)
    account_id: str = ""
    prowler_version: str = ""
    time: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id, "status": self.status, "region": self.region,
            "resource_uid": self.resource_uid, "resource_type": self.resource_type, "resource_name": self.resource_name,
            "message": self.message, "prowler_severity": self.severity, "muted": self.muted,
        }


def _first_resource(item: dict[str, Any]) -> dict[str, Any]:
    res = item.get("resources") or [{}]
    return res[0] if isinstance(res, list) and res and isinstance(res[0], dict) else {}


def parse_item(item: dict[str, Any]) -> CheckResult | None:
    meta = item.get("metadata") or {}
    check_id = meta.get("event_code") or (item.get("finding_info") or {}).get("analytic", {}).get("uid", "")
    status = str(item.get("status_code") or "").upper()
    if not check_id or status not in {"PASS", "FAIL", "MANUAL"}:
        return None
    r = _first_resource(item)
    cloud = item.get("cloud") or {}
    unmapped = item.get("unmapped") or {}
    return CheckResult(
        check_id=check_id,
        status=status,
        region=r.get("region") or cloud.get("region") or "global",
        resource_uid=r.get("uid") or "",
        resource_type=r.get("type") or "",
        resource_name=r.get("name") or "",
        message=item.get("status_detail") or item.get("message") or "",
        severity=str(item.get("severity") or ""),
        # Prowler marks muted (accepted-risk) findings with status "Suppressed".
        muted=str(item.get("status") or "").lower() == "suppressed" or bool(unmapped.get("muted")),
        compliance=unmapped.get("compliance") or {},
        account_id=str((cloud.get("account") or {}).get("uid") or unmapped.get("provider_uid") or ""),
        prowler_version=str((meta.get("product") or {}).get("version") or ""),
        time=str(item.get("time_dt") or ""),
    )


def load(path: str | Path) -> list[CheckResult]:
    """Load one OCSF file: a JSON array (Prowler's default) or one JSON object per line."""
    text = Path(path).read_text(encoding="utf-8").strip()
    if not text:
        return []
    if text.startswith("["):
        items = json.loads(text)
    else:
        items = [json.loads(line) for line in text.splitlines() if line.strip()]
    out = []
    for it in items:
        if isinstance(it, dict):
            cr = parse_item(it)
            if cr:
                out.append(cr)
    return out


def cis_refs(results: list[CheckResult]) -> dict[str, list[str]]:
    """Check ID -> CIS AWS Foundations references, taken from Prowler's own compliance mapping
    (the newest CIS version present), so the report never carries a hand-typed control number."""
    out: dict[str, list[str]] = {}
    for r in results:
        if r.check_id in out:
            continue
        keys = sorted((k for k in r.compliance if k.startswith("CIS-") and k[4:5].isdigit()),
                      key=lambda k: [int(x) if x.isdigit() else 0 for x in k[4:].split(".")])
        if keys:
            out[r.check_id] = [f"{keys[-1]} {ref}" for ref in r.compliance[keys[-1]]]
    return out
