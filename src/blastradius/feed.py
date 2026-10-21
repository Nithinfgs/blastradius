"""Advisory feed loading and validation.

A feed is a JSON document describing one supply-chain incident. See
``docs/FEED_FORMAT.md`` for the schema.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from importlib import resources
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .versions import normalize_name, validate_range

ECOSYSTEMS = ("pypi", "npm", "crates", "go")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class FeedError(ValueError):
    """Raised when a feed file is unreadable or invalid."""


@dataclass
class PackageIOC:
    ecosystem: str
    name: str
    versions: List[str] = field(default_factory=list)
    ranges: List[str] = field(default_factory=list)
    note: str = ""


@dataclass
class FileIOC:
    name: str
    sha256: List[str] = field(default_factory=list)
    distinctive: bool = False
    note: str = ""


@dataclass
class Feed:
    id: str
    title: str
    source: str
    packages: List[PackageIOC]
    window_start: Optional[datetime] = None
    window_end: Optional[datetime] = None
    files: List[FileIOC] = field(default_factory=list)
    host_artifacts: List[str] = field(default_factory=list)
    domains: List[str] = field(default_factory=list)
    steals: List[str] = field(default_factory=list)
    remediation: List[str] = field(default_factory=list)
    caveats: List[str] = field(default_factory=list)


def _parse_time(value: Any, where: str) -> datetime:
    if not isinstance(value, str):
        raise FeedError(f"{where}: expected an ISO-8601 string")
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise FeedError(f"{where}: invalid timestamp {value!r}") from exc
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _str_list(obj: Dict[str, Any], key: str, where: str) -> List[str]:
    value = obj.get(key, [])
    if not isinstance(value, list) or not all(isinstance(v, str) and v for v in value):
        raise FeedError(f"{where}.{key}: expected a list of non-empty strings")
    return list(value)


def parse_feed(data: Any) -> Feed:
    """Validate a decoded JSON document and build a :class:`Feed`."""
    if not isinstance(data, dict):
        raise FeedError("feed must be a JSON object")
    for key in ("id", "title", "packages"):
        if key not in data:
            raise FeedError(f"missing required field {key!r}")
    for key in ("id", "title"):
        if not isinstance(data[key], str) or not data[key].strip():
            raise FeedError(f"{key}: expected a non-empty string")
    if not re.match(r"^[A-Za-z0-9][A-Za-z0-9._-]*$", data["id"]):
        raise FeedError("id: use letters, digits, '.', '_' and '-' only")

    packages: List[PackageIOC] = []
    raw_packages = data["packages"]
    if not isinstance(raw_packages, list):
        raise FeedError("packages: expected a list")
    for i, raw in enumerate(raw_packages):
        where = f"packages[{i}]"
        if not isinstance(raw, dict):
            raise FeedError(f"{where}: expected an object")
        eco = raw.get("ecosystem")
        if eco not in ECOSYSTEMS:
            raise FeedError(f"{where}.ecosystem: must be one of {', '.join(ECOSYSTEMS)}")
        name = raw.get("name")
        if not isinstance(name, str) or not name.strip():
            raise FeedError(f"{where}.name: expected a non-empty string")
        versions = _str_list(raw, "versions", where)
        ranges = _str_list(raw, "ranges", where)
        if not versions and not ranges:
            raise FeedError(f"{where}: needs at least one of 'versions' or 'ranges'")
        for spec in ranges:
            err = validate_range(spec)
            if err:
                raise FeedError(f"{where}.ranges: {err}")
        packages.append(
            PackageIOC(eco, normalize_name(eco, name), versions, ranges, str(raw.get("note", "")))
        )

    files: List[FileIOC] = []
    raw_files = data.get("files", [])
    if not isinstance(raw_files, list):
        raise FeedError("files: expected a list")
    for i, raw in enumerate(raw_files):
        where = f"files[{i}]"
        if not isinstance(raw, dict) or not isinstance(raw.get("name"), str) or not raw["name"]:
            raise FeedError(f"{where}: expected an object with a 'name'")
        hashes = [h.lower() for h in _str_list(raw, "sha256", where)]
        for h in hashes:
            if not _SHA256_RE.match(h):
                raise FeedError(f"{where}.sha256: {h!r} is not a 64-character hex digest")
        files.append(
            FileIOC(raw["name"], hashes, bool(raw.get("distinctive", False)), str(raw.get("note", "")))
        )

    window = data.get("window", {})
    if not isinstance(window, dict):
        raise FeedError("window: expected an object")
    start = _parse_time(window["start"], "window.start") if "start" in window else None
    end = _parse_time(window["end"], "window.end") if "end" in window else None
    if start and end and end < start:
        raise FeedError("window: 'end' is before 'start'")

    return Feed(
        id=data["id"],
        title=data["title"],
        source=str(data.get("source", "")),
        packages=packages,
        window_start=start,
        window_end=end,
        files=files,
        host_artifacts=_str_list(data, "host_artifacts", "feed"),
        domains=[d.lower() for d in _str_list(data, "domains", "feed")],
        steals=_str_list(data, "steals", "feed"),
        remediation=_str_list(data, "remediation", "feed"),
        caveats=_str_list(data, "caveats", "feed"),
    )


def load_feed_file(path: Path) -> Feed:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise FeedError(f"cannot read {path}: {exc.strerror or exc}") from exc
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise FeedError(f"{path}: invalid JSON ({exc})") from exc
    try:
        return parse_feed(data)
    except FeedError as exc:
        raise FeedError(f"{path}: {exc}") from exc


def bundled_feed_names() -> List[str]:
    root = resources.files("blastradius").joinpath("feeds")
    return sorted(p.name[:-5] for p in root.iterdir() if p.name.endswith(".json"))


def load_bundled_feed(name: str) -> Feed:
    root = resources.files("blastradius").joinpath("feeds")
    target = root.joinpath(f"{name}.json")
    if not target.is_file():
        raise FeedError(f"no bundled feed named {name!r} (have: {', '.join(bundled_feed_names())})")
    try:
        data = json.loads(target.read_text(encoding="utf-8"))
        return parse_feed(data)
    except (json.JSONDecodeError, FeedError) as exc:
        raise FeedError(f"bundled feed {name}: {exc}") from exc


def resolve_feeds(specs: List[str]) -> Tuple[List[Feed], List[str]]:
    """Resolve ``--feed`` arguments (bundled names or file paths); none means all bundled."""
    feeds: List[Feed] = []
    labels: List[str] = []
    if not specs:
        specs = bundled_feed_names()
    for spec in specs:
        path = Path(spec).expanduser()
        if path.suffix == ".json" or path.exists():
            feeds.append(load_feed_file(path))
        else:
            feeds.append(load_bundled_feed(spec))
        labels.append(spec)
    return feeds, labels
