from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any, Dict

import pytest

from blastradius.feed import Feed, parse_feed

BAD_PTH = b"import cook  # benign test fixture, not malware\n"
BAD_PTH_SHA = hashlib.sha256(BAD_PTH).hexdigest()


def feed_data(**overrides: Any) -> Dict[str, Any]:
    data: Dict[str, Any] = {
        "id": "test-incident",
        "title": "Test incident",
        "window": {"start": "2026-10-21T11:39:00Z", "end": "2026-10-21T13:40:00Z"},
        "packages": [
            {"ecosystem": "pypi", "name": "Evil_Pkg", "versions": ["1.107.0"]},
            {"ecosystem": "npm", "name": "@scope/bad", "ranges": [">=2.0.0,<2.0.5"]},
            {"ecosystem": "crates", "name": "badcrate", "versions": ["0.3.1"]},
        ],
        "files": [
            {"name": "cook.pth", "sha256": [BAD_PTH_SHA], "distinctive": True},
            {"name": "sitecustomize.py", "sha256": ["0" * 64]},
        ],
        "host_artifacts": [],
        "domains": ["c2.example.test"],
        "steals": ["ssh", "aws", "browser"],
        "remediation": ["Remove it."],
    }
    data.update(overrides)
    return data


@pytest.fixture
def feed() -> Feed:
    return parse_feed(feed_data())


@pytest.fixture
def feed_file(tmp_path: Path) -> Path:
    path = tmp_path / "feed.json"
    path.write_text(json.dumps(feed_data()))
    return path


def make_dist(site: Path, name: str, version: str, when: float | None = None) -> Path:
    dist = site / f"{name}-{version}.dist-info"
    dist.mkdir(parents=True)
    (dist / "METADATA").write_text(f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n\nbody\n")
    record = dist / "RECORD"
    record.write_text("")
    if when is not None:
        os.utime(record, (when, when))
    return dist


@pytest.fixture
def home(tmp_path: Path) -> Path:
    h = tmp_path / "home"
    h.mkdir()
    return h
