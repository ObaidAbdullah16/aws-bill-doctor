"""The "AWS Health Check" bundle: cost (S1) and security (S8) from one read-only role, one summary page."""
from __future__ import annotations

from pathlib import Path

from .. import __version__
from ..report import _env
from ..report import write_all as write_cost
from ..scanner import ScanResult
from .assess import Assessment
from .report import write_all as write_security


def to_html(cost: ScanResult, sec: Assessment) -> str:
    return _env().get_template("healthcheck.html.j2").render(c=cost, s=sec, version=__version__)


def write_bundle(cost: ScanResult, sec: Assessment, out_dir: str) -> list[Path]:
    out = Path(out_dir)
    files = write_cost(cost, str(out / "cost")) + write_security(sec, str(out / "security"))
    index = out / "index.html"
    index.write_text(to_html(cost, sec), encoding="utf-8")
    return [index, *files]
