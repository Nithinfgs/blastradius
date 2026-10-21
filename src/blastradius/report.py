"""Render scan results as text, Markdown or JSON."""

from __future__ import annotations

import json
from typing import Dict, List

from . import __version__
from .creds import UNLOCATABLE
from .feed import Feed
from .models import Finding, ScanResult, severity_rank

_COLORS = {"critical": "1;31", "high": "31", "medium": "33", "low": "36", "info": "2"}


def _paint(text: str, code: str, color: bool) -> str:
    return f"\033[{code}m{text}\033[0m" if color else text


def _verdict(result: ScanResult, feed: Feed) -> str:
    sevs = [f.severity for f in result.findings if f.advisory == feed.id]
    if not sevs:
        return "NOT FOUND"
    top = max(sevs, key=severity_rank)
    if top in ("critical",):
        return "COMPROMISED"
    if top == "high":
        return "EXPOSED"
    return "AT RISK"


def to_json(result: ScanResult) -> str:
    payload = {
        "tool": "blastradius",
        "version": __version__,
        "advisories": [
            {"id": f.id, "title": f.title, "verdict": _verdict(result, f), "source": f.source}
            for f in result.feeds
        ],
        "stats": result.stats.__dict__,
        "findings": [f.to_dict() for f in result.findings],
        "credentials_present": result.credentials,
        "credentials_not_locatable": result.credential_classes_unlocated,
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def _group(findings: List[Finding]) -> Dict[str, List[Finding]]:
    grouped: Dict[str, List[Finding]] = {}
    for f in findings:
        grouped.setdefault(f.advisory, []).append(f)
    return grouped


def to_text(result: ScanResult, color: bool = False, markdown: bool = False) -> str:
    lines: List[str] = []
    h = (lambda t: f"## {t}") if markdown else (lambda t: t)
    lines.append(f"blastradius {__version__}")
    s = result.stats
    lines.append(
        f"Scanned {s.dirs} directories, {s.files} files, {s.packages_seen} installed packages, "
        f"{s.lockfiles} lockfiles ({s.errors} unreadable)."
    )
    lines.append("")
    grouped = _group(result.findings)
    for feed in result.feeds:
        verdict = _verdict(result, feed)
        code = {"COMPROMISED": "1;31", "EXPOSED": "31", "AT RISK": "33", "NOT FOUND": "32"}[verdict]
        lines.append(h(f"{feed.id}: {_paint(verdict, code, color)}"))
        lines.append(f"  {feed.title}")
        if feed.window_start:
            end = feed.window_end.isoformat() if feed.window_end else "ongoing"
            lines.append(f"  Live window: {feed.window_start.isoformat()} to {end}")
        for f in grouped.get(feed.id, []):
            tag = _paint(f"[{f.severity.upper()}]", _COLORS[f.severity], color)
            lines.append(f"  {tag} {f.summary}")
            lines.append(f"      {f.path}")
            if f.installed_at:
                lines.append(f"      timestamp: {f.installed_at.isoformat()} ({f.timing or 'n/a'})")
            if f.detail:
                lines.append(f"      {f.detail}")
        lines.append("")

    compromised = [f for f in result.feeds if _verdict(result, f) in ("COMPROMISED", "EXPOSED")]
    if compromised:
        lines.append(h("What to do"))
        for feed in compromised:
            for step in feed.remediation:
                lines.append(f"  - {step}")
        if result.credentials or result.credential_classes_unlocated:
            lines.append("")
            lines.append(h("Rotation checklist (credential stores that exist on this machine)"))
            lines.append("  Paths only; blastradius never opens these files.")
            for cls, paths in sorted(result.credentials.items()):
                lines.append(f"  - {cls}:")
                for p in paths:
                    lines.append(f"      {p}")
            for cls in result.credential_classes_unlocated:
                lines.append(f"  - {cls}: {UNLOCATABLE.get(cls, 'cannot be located by a file scan')}")
        lines.append("")
    for feed in result.feeds:
        for caveat in feed.caveats:
            lines.append(f"Note ({feed.id}): {caveat}")
    if not result.findings:
        lines.append(
            "No indicators found. Absence of evidence is limited to the scanned roots and the feed's IOCs."
        )
    return "\n".join(lines).rstrip() + "\n"
