"""Approximate on-demand prices (USD) used for savings estimates.

Source: AWS public price list pages, checked October 2026. Prices change and vary
by region, so every number in a report is labelled an estimate. To update, edit the
tables below; anything missing for a region falls back to us-east-1 and the report
says so.
"""
from __future__ import annotations

from typing import Any

PRICES_AS_OF = "2026-10"

_TABLE: dict[str, dict[str, Any]] = {
    "us-east-1": {
        "ebs_gb_month": {"gp2": 0.10, "gp3": 0.08, "io1": 0.125, "io2": 0.125, "st1": 0.045, "sc1": 0.015, "standard": 0.05},
        # Provisioned performance: io1/io2 IOPS (io2 is tiered, see ScanContext.volume_cost) and
        # gp3 IOPS above 3,000 / throughput above 125 MiB/s.
        "ebs_iops_month": {"io1": 0.065, "io2": 0.065, "gp3": 0.005},
        "ebs_throughput_month": {"gp3": 0.04},
        "snapshot_gb_month": 0.05,
        "public_ipv4_hour": 0.005,
        "nat_hour": 0.045,
        "alb_hour": 0.0225,
        "nlb_hour": 0.0225,
        "clb_hour": 0.025,
        "logs_gb_month": 0.03,
        "ec2_hour": {
            "t2.micro": 0.0116, "t2.small": 0.023, "t2.medium": 0.0464, "t2.large": 0.0928, "t2.xlarge": 0.1856,
            "t3.micro": 0.0104, "t3.small": 0.0208, "t3.medium": 0.0416, "t3.large": 0.0832, "t3.xlarge": 0.1664,
            "t4g.micro": 0.0084, "t4g.small": 0.0168, "t4g.medium": 0.0336, "t4g.large": 0.0672,
            "m4.large": 0.10, "m5.large": 0.096, "m6i.large": 0.096, "m7g.large": 0.0816,
            "c4.large": 0.10, "c5.large": 0.085, "c6i.large": 0.085,
            "r4.large": 0.133, "r5.large": 0.126, "r6i.large": 0.126,
        },
        "rds_hour": {
            "db.t3.micro": 0.018, "db.t3.small": 0.036, "db.t3.medium": 0.072,
            "db.t4g.micro": 0.016, "db.t4g.small": 0.032, "db.t4g.medium": 0.065,
        },
    },
    "ap-south-1": {
        "ebs_gb_month": {"gp2": 0.114, "gp3": 0.0912, "io1": 0.131, "st1": 0.051, "sc1": 0.0174},
        "snapshot_gb_month": 0.05,
        "public_ipv4_hour": 0.005,
        "nat_hour": 0.056,
        "ec2_hour": {
            "t2.micro": 0.0124, "t2.small": 0.0248, "t2.medium": 0.0496, "t2.large": 0.0992,
            "t3.micro": 0.0112, "t3.small": 0.0224, "t3.medium": 0.0448, "t3.large": 0.0896, "t3.xlarge": 0.1792,
        },
        "rds_hour": {"db.t4g.micro": 0.021, "db.t3.micro": 0.021},
    },
}

# Previous-generation families and the current family that usually replaces them.
UPGRADE_PATH = {
    "t2": "t3", "m3": "m6i", "m4": "m6i", "c3": "c6i", "c4": "c6i",
    "r3": "r6i", "r4": "r6i", "i2": "i4i", "d2": "d3", "x1": "x2iedn", "p2": "g5", "g3": "g5",
}


class Prices:
    def __init__(self, table: dict[str, dict[str, Any]] | None = None):
        self.table = table or _TABLE

    def get(self, region: str, key: str, *sub: str) -> tuple[float | None, bool]:
        """Return (price, used_fallback)."""
        for i, reg in enumerate([region, "us-east-1"]):
            node: Any = self.table.get(reg, {}).get(key)
            for s in sub:
                node = node.get(s) if isinstance(node, dict) else None
            if isinstance(node, (int, float)):
                return float(node), i == 1 and region != "us-east-1"
        return None, False
