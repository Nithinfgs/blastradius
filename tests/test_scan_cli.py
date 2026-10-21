from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from blastradius.cli import main
from blastradius.feed import parse_feed
from blastradius.scan import scan

from .conftest import BAD_PTH, feed_data, make_dist

IN_WINDOW = datetime(2026, 10, 21, 12, 0, tzinfo=timezone.utc).timestamp()
AFTER_PULL = datetime(2026, 10, 22, 9, 0, tzinfo=timezone.utc).timestamp()


def run(feed, home: Path, **kw):
    return scan([feed], [str(home)], home=str(home), **kw)


def by_kind(result, kind):
    return [f for f in result.findings if f.kind == kind]


def test_clean_machine(feed, home: Path):
    make_dist(home / "venv/lib/python3.12/site-packages", "requests", "2.31.0")
    result = run(feed, home)
    assert result.findings == []
    assert result.stats.packages_seen == 1


@pytest.mark.parametrize(
    "stamp, expected",
    [
        (IN_WINDOW, "inside-window"),
        (AFTER_PULL, "after-pull"),
        (datetime(2026, 10, 1, tzinfo=timezone.utc).timestamp(), "before-upload"),
    ],
)
def test_installed_version_with_timing(feed, home: Path, monkeypatch, stamp, expected):
    # st_birthtime on macOS ignores utime(); pin the clock source so timing is deterministic.
    monkeypatch.setattr(
        "blastradius.scan._birth_time", lambda path: datetime.fromtimestamp(stamp, tz=timezone.utc)
    )
    site = home / "proj/.venv/lib/python3.12/site-packages"
    make_dist(site, "Evil_Pkg", "1.107.0")
    f = by_kind(run(feed, home), "installed")[0]
    assert f.severity == "high" and f.timing == expected
    assert f.package == "evil-pkg" and "proj/.venv" in f.path


def test_other_version_not_flagged(feed, home: Path):
    make_dist(home / "v/lib/python3.12/site-packages", "evil_pkg", "1.106.2")
    assert run(feed, home).findings == []


def test_ioc_file_hash_escalates_to_critical_and_correlates(feed, home: Path):
    site = home / "v/lib/python3.12/site-packages"
    make_dist(site, "evil-pkg", "1.107.0")
    (site / "cook.pth").write_bytes(BAD_PTH)
    result = run(feed, home)
    ioc = by_kind(result, "ioc-file")[0]
    assert ioc.severity == "critical" and "SHA-256" in ioc.summary
    assert result.max_severity() == "critical"


def test_ioc_file_name_only_is_high_when_distinctive(feed, home: Path):
    site = home / "v/lib/python3.12/site-packages"
    site.mkdir(parents=True)
    (site / "cook.pth").write_text("different content")
    ioc = by_kind(run(feed, home), "ioc-file")[0]
    assert ioc.severity == "high" and "distinctive" in ioc.summary


def test_common_name_with_other_hash_is_ignored_unless_correlated(feed, home: Path):
    site = home / "v/lib/python3.12/site-packages"
    site.mkdir(parents=True)
    (site / "sitecustomize.py").write_text("# legit site customisation")
    assert run(feed, home).findings == []


def test_ioc_file_outside_site_packages_is_ignored(feed, home: Path):
    (home / "notes").mkdir()
    (home / "notes/cook.pth").write_bytes(BAD_PTH)
    assert run(feed, home).findings == []


def test_lockfile_and_cache_and_node_modules(feed, home: Path):
    proj = home / "app"
    proj.mkdir()
    (proj / "requirements.txt").write_text("evil-pkg==1.107.0\n")
    (proj / "package-lock.json").write_text(
        json.dumps({"packages": {"node_modules/@scope/bad": {"version": "2.0.3"}}})
    )
    cache = home / ".cache/pip-wheels"
    cache.mkdir(parents=True)
    (cache / "evil_pkg-1.107.0-py3-none-any.whl").write_bytes(b"x")
    nm = proj / "node_modules/@scope/bad"
    nm.mkdir(parents=True)
    (nm / "package.json").write_text(json.dumps({"name": "@scope/bad", "version": "2.0.4"}))
    (proj / "node_modules/@scope/safe").mkdir()
    (proj / "node_modules/@scope/safe/package.json").write_text(
        json.dumps({"name": "@scope/bad", "version": "2.0.5"})
    )

    result = run(feed, home)
    kinds = sorted((f.kind, f.severity) for f in result.findings)
    assert kinds == [
        ("cache", "medium"),
        ("lockfile", "medium"),
        ("lockfile", "medium"),
        ("node_modules", "high"),
    ]


def test_uv_style_cache_dist_info_is_cache_not_installed(feed, home: Path):
    make_dist(home / ".cache/uv/archive-v0/abc123", "evil_pkg", "1.107.0")
    f = run(feed, home).findings[0]
    assert f.kind == "cache" and f.severity == "medium"


def test_npm_cacache_index(feed, home: Path):
    idx = home / ".npm/_cacache/index-v5/ab/cd"
    idx.mkdir(parents=True)
    (idx / "entry").write_text(
        'deadbeef\t{"key":"make-fetch-happen:request-cache:https://registry.npmjs.org/@scope/bad/-/bad-2.0.3.tgz"}'
    )
    f = by_kind(run(feed, home), "cache")[0]
    assert f.package == "@scope/bad" and f.version == "2.0.3"


def test_host_artifacts_and_domain_in_history(home: Path):
    marker = home / "marker.lock"
    marker.write_text("")
    feed = parse_feed(feed_data(host_artifacts=[str(home / "marker.*")]))
    (home / ".zsh_history").write_text("ls\ncurl https://C2.example.test/x\n")
    result = run(feed, home)
    kinds = {f.kind: f for f in result.findings}
    assert kinds["host-artifact"].severity == "critical"
    assert kinds["domain"].severity == "high" and "line 2" in kinds["domain"].detail
    assert run(feed, home, host_checks=False).findings == []


def test_credential_checklist_lists_paths_not_contents(feed, home: Path):
    site = home / "v/lib/python3.12/site-packages"
    make_dist(site, "evil-pkg", "1.107.0")
    (home / ".ssh").mkdir()
    (home / ".ssh/id_ed25519").write_text("TOP-SECRET-KEY-MATERIAL")
    (home / ".ssh/id_ed25519.pub").write_text("pub")
    result = run(feed, home)
    assert result.credentials == {"ssh": [str(home / ".ssh/id_ed25519")]}
    assert "browser" in result.credential_classes_unlocated
    from blastradius.report import to_json, to_text

    assert "TOP-SECRET" not in to_json(result) + to_text(result)


def test_symlink_loops_and_unreadable_roots_do_not_crash(feed, home: Path):
    (home / "a").mkdir()
    (home / "a/loop").symlink_to(home)
    assert run(feed, home).findings == []


def test_json_report_roundtrips(feed, home: Path):
    make_dist(home / "v/lib/python3.12/site-packages", "evil-pkg", "1.107.0")
    from blastradius.report import to_json

    payload = json.loads(to_json(run(feed, home)))
    assert payload["advisories"][0]["verdict"] == "EXPOSED"
    assert payload["findings"][0]["package"] == "evil-pkg"


# ---- CLI ---------------------------------------------------------------------------------


def test_cli_exit_codes(feed_file: Path, home: Path, capsys):
    assert main(["scan", "--feed", str(feed_file), "--root", str(home), "--no-host-checks"]) == 0
    make_dist(home / "v/lib/python3.12/site-packages", "evil-pkg", "1.107.0")
    assert main(["scan", "--feed", str(feed_file), "--root", str(home), "--no-host-checks"]) == 1
    out = capsys.readouterr().out
    assert "EXPOSED" in out and "Rotation checklist" in out
    assert (
        main(
            [
                "scan",
                "--feed",
                str(feed_file),
                "--root",
                str(home),
                "--fail-on",
                "critical",
                "--no-host-checks",
            ]
        )
        == 0
    )


def test_cli_usage_errors(tmp_path: Path, capsys):
    assert main(["scan", "--feed", "nonexistent-feed"]) == 2
    assert main(["scan", "--feed", str(tmp_path / "x.json")]) == 2
    assert main(["scan", "--root", str(tmp_path / "missing")]) == 2
    err = capsys.readouterr().err
    assert "no bundled feed" in err and "not a directory" in err


def test_cli_json_and_markdown(feed_file: Path, home: Path, capsys):
    make_dist(home / "v/lib/python3.12/site-packages", "evil-pkg", "1.107.0")
    main(["scan", "--feed", str(feed_file), "--root", str(home), "--format", "json", "--no-host-checks"])
    assert json.loads(capsys.readouterr().out)["findings"]
    main(["scan", "--feed", str(feed_file), "--root", str(home), "--format", "markdown", "--no-host-checks"])
    assert "## test-incident" in capsys.readouterr().out


def test_cli_validate_and_feeds(feed_file: Path, tmp_path: Path, capsys):
    assert main(["validate", str(feed_file)]) == 0
    bad = tmp_path / "bad.json"
    bad.write_text("[]")
    assert main(["validate", str(bad)]) == 2
    assert main(["feeds"]) == 0
    out = capsys.readouterr()
    assert out.out.startswith("ok:") and "litellm" in out.out
    assert "invalid" in out.err


def test_cli_requires_command():
    with pytest.raises(SystemExit):
        main([])
