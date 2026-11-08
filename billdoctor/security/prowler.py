"""Run Prowler with the curated check list.

Prowler is not a Python dependency of this package: it is a large application with its own pinned
dependencies, so it is best installed on its own (`pipx install prowler`). This module only builds the
command line, runs it, and finds the JSON-OCSF file it writes.
"""
from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

from .controls import prowler_checks

INSTALL_HINT = "Prowler is not installed. Install it on its own with:  pipx install prowler   (or: pip install prowler)"


def build_command(out_dir: str | Path, regions: list[str] | None = None, profile: str | None = None,
                  role_arn: str | None = None, external_id: str | None = None,
                  prowler: str = "prowler", output_name: str = "prowler") -> list[str]:
    """The exact command we run. Read-only: Prowler only calls Describe/List/Get APIs."""
    cmd = [prowler, "aws", "--no-banner", "--checks", *prowler_checks(),
           "--output-formats", "json-ocsf", "--output-directory", str(out_dir), "--output-filename", output_name]
    if regions:
        cmd += ["--filter-region", *regions]
    if profile:
        cmd += ["--profile", profile]
    if role_arn:
        cmd += ["--role", role_arn, "--role-session-name", "security-baseline-check"]
        if external_id:
            cmd += ["--external-id", external_id]
    return cmd


def redact(cmd: list[str]) -> str:
    """Printable command line without the external ID (it is a shared secret)."""
    out, hide = [], False
    for part in cmd:
        out.append("****" if hide else part)
        hide = part == "--external-id"
    return " ".join(out)


def run(out_dir: str | Path, **kwargs) -> Path:
    """Run Prowler and return the path of its JSON-OCSF output.

    Prowler exits with code 3 when it found failing checks; that is a normal result, not an error.
    """
    exe = shutil.which("prowler")
    if not exe:
        raise FileNotFoundError(INSTALL_HINT)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    cmd = build_command(out, prowler=exe, **kwargs)
    print("Running: " + redact(cmd), file=sys.stderr)
    proc = subprocess.run(cmd, check=False)
    if proc.returncode not in (0, 3):
        raise RuntimeError(f"prowler exited with code {proc.returncode}")
    found = sorted(out.glob("*.ocsf.json"), key=lambda p: p.stat().st_mtime)
    if not found:
        raise RuntimeError(f"prowler wrote no *.ocsf.json file in {out}")
    return found[-1]
