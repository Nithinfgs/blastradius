from __future__ import annotations

import json
from pathlib import Path

import pytest

from blastradius.feed import (
    FeedError,
    bundled_feed_names,
    load_bundled_feed,
    load_feed_file,
    parse_feed,
    resolve_feeds,
)
from blastradius.versions import in_range, normalize_name, parse_version, validate_range, versions_equal

from .conftest import feed_data


def test_normalize_pypi_names():
    assert normalize_name("pypi", "Evil_Pkg.X") == "evil-pkg-x"
    assert normalize_name("npm", "@Scope/Bad") == "@scope/bad"


@pytest.mark.parametrize(
    "version, spec, expected",
    [
        ("1.82.7", ">=1.82.7,<1.83", True),
        ("1.83.0", ">=1.82.7,<1.83", False),
        ("1.82.6", ">=1.82.7", False),
        ("2.0.0rc1", "<2.0.0", True),
        ("2.0.0", "<2.0.0", False),
        ("2.0.0.post1", ">2.0.0", True),
        ("2.0.0.dev3", "<2.0.0a1", True),
        ("1.0", "==1.0.0", True),
        ("1.0.1", "!=1.0.1", False),
        ("not-a-version", ">=1.0", False),
    ],
)
def test_in_range(version, spec, expected):
    assert in_range(version, spec) is expected


def test_prerelease_ordering():
    keys = [parse_version(v) for v in ["1.0.dev1", "1.0a1", "1.0b2", "1.0rc1", "1.0", "1.0.post1"]]
    assert keys == sorted(keys)


def test_versions_equal_handles_padding_and_prefix():
    assert versions_equal("v1.2", "1.2.0")
    assert not versions_equal("1.2.1", "1.2.0")


def test_validate_range():
    assert validate_range(">=1.0,<2") is None
    assert validate_range("") == "empty range"
    assert "cannot parse" in (validate_range("~1.0") or "")


def test_parse_feed_ok(feed):
    assert feed.id == "test-incident"
    assert feed.packages[0].name == "evil-pkg"
    assert feed.window_start is not None and feed.window_start.tzinfo is not None
    assert feed.domains == ["c2.example.test"]


@pytest.mark.parametrize(
    "mutate, message",
    [
        (lambda d: d.pop("id"), "missing required field 'id'"),
        (lambda d: d.update(id="bad id!"), "id:"),
        (lambda d: d.update(packages="x"), "packages: expected a list"),
        (lambda d: d["packages"][0].update(ecosystem="rubygems"), "ecosystem"),
        (lambda d: d["packages"][0].update(versions=[]), "at least one"),
        (lambda d: d["packages"][1].update(ranges=["~2.0"]), "ranges"),
        (lambda d: d["files"][0].update(sha256=["abc"]), "64-character"),
        (lambda d: d.update(window={"start": "yesterday"}), "invalid timestamp"),
        (
            lambda d: d.update(window={"start": "2026-02-01T00:00:00Z", "end": "2026-01-01T00:00:00Z"}),
            "before",
        ),
    ],
)
def test_parse_feed_rejects_bad_input(mutate, message):
    data = feed_data()
    mutate(data)
    with pytest.raises(FeedError, match=message):
        parse_feed(data)


def test_feed_must_be_object():
    with pytest.raises(FeedError):
        parse_feed([])


def test_load_feed_file_errors(tmp_path: Path):
    with pytest.raises(FeedError, match="cannot read"):
        load_feed_file(tmp_path / "nope.json")
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    with pytest.raises(FeedError, match="invalid JSON"):
        load_feed_file(bad)


def test_bundled_feeds_are_valid():
    names = bundled_feed_names()
    assert names
    for name in names:
        assert load_bundled_feed(name).packages
    with pytest.raises(FeedError, match="no bundled feed"):
        load_bundled_feed("does-not-exist")


def test_resolve_feeds_defaults_to_bundled_and_accepts_paths(feed_file: Path):
    feeds, _ = resolve_feeds([])
    assert len(feeds) == len(bundled_feed_names())
    feeds, labels = resolve_feeds([str(feed_file)])
    assert feeds[0].id == "test-incident" and labels == [str(feed_file)]
    json.loads(feed_file.read_text())
