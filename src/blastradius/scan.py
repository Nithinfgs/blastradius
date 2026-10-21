"""Single-pass filesystem sweep that matches what it finds against advisory feeds."""

from __future__ import annotations

import glob
import hashlib
import json
import os
import re
from datetime import datetime, timezone
from typing import Callable, Dict, Iterable, List, Optional, Set, Tuple

from . import creds
from .feed import Feed, PackageIOC
from .lockfiles import parse_lockfile, parser_for
from .models import Finding, ScanResult, ScanStats, severity_rank
from .versions import in_range, normalize_name, versions_equal

PRUNE_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".Trash",
    "__pycache__",
    ".Spotlight-V100",
    ".fseventsd",
    ".mypy_cache",
    ".ruff_cache",
    ".pytest_cache",
    ".tox",
}
PRUNE_SUFFIXES = (".photoslibrary", ".app")
MAX_TEXT_BYTES = 64 * 1024 * 1024
MAX_LOCKFILE_BYTES = 32 * 1024 * 1024
_SITE_DIRS = {"site-packages", "dist-packages"}
_NPM_CACHE_RE = re.compile(
    r"registry\.npmjs\.org/((?:@[^/\"\s]+/)?[^/\"\s]+)/-/[^/\"\s]+?-(\d[^/\"\s]*?)\.tgz"
)
_SDIST_EXTS = (".tar.gz", ".zip", ".tgz", ".crate")


def _birth_time(path: str) -> Optional[datetime]:
    try:
        st = os.stat(path)
    except OSError:
        return None
    stamp = getattr(st, "st_birthtime", None) or st.st_mtime
    return datetime.fromtimestamp(stamp, tz=timezone.utc)


def _timing(feed: Feed, when: Optional[datetime]) -> str:
    if when is None or feed.window_start is None:
        return "unknown"
    if when < feed.window_start:
        return "before-upload"
    if feed.window_end is not None and when > feed.window_end:
        return "after-pull"
    return "inside-window"


def _sha256(path: str) -> Optional[str]:
    digest = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                digest.update(chunk)
    except OSError:
        return None
    return digest.hexdigest()


def _read_text(path: str, limit: int) -> Optional[str]:
    try:
        if os.path.getsize(path) > limit:
            return None
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return None


class _Matcher:
    """Index of every feed's package IOCs for fast lookup."""

    def __init__(self, feeds: List[Feed]) -> None:
        self.feeds = feeds
        self._by_key: Dict[Tuple[str, str], List[Tuple[Feed, PackageIOC]]] = {}
        self.file_names: Dict[str, List[Tuple[Feed, int]]] = {}
        for feed in feeds:
            for ioc in feed.packages:
                self._by_key.setdefault((ioc.ecosystem, ioc.name), []).append((feed, ioc))
            for idx, fioc in enumerate(feed.files):
                self.file_names.setdefault(fioc.name.lower(), []).append((feed, idx))

    def match(self, ecosystem: str, name: str, version: str) -> List[Tuple[Feed, PackageIOC]]:
        hits = []
        for feed, ioc in self._by_key.get((ecosystem, normalize_name(ecosystem, name)), []):
            if any(versions_equal(version, v) for v in ioc.versions) or any(
                in_range(version, r) for r in ioc.ranges
            ):
                hits.append((feed, ioc))
        return hits


def _split_dist_name(dirname: str) -> Optional[Tuple[str, str]]:
    base = dirname.rsplit(".", 1)[0]
    if "-" not in base:
        return None
    name, version = base.split("-", 1)
    return name, version


def _read_dist_metadata(dirpath: str, dirname: str) -> Optional[Tuple[str, str]]:
    meta_name = "METADATA" if dirname.endswith(".dist-info") else "PKG-INFO"
    name = version = ""
    try:
        with open(os.path.join(dirpath, dirname, meta_name), encoding="utf-8", errors="replace") as fh:
            for _ in range(60):
                line = fh.readline()
                if not line or not line.strip():
                    break
                if line.startswith("Name:"):
                    name = line.split(":", 1)[1].strip()
                elif line.startswith("Version:"):
                    version = line.split(":", 1)[1].strip()
                if name and version:
                    break
    except OSError:
        pass
    if name and version:
        return name, version
    return _split_dist_name(dirname)


def _artifact_pin(filename: str) -> Optional[Tuple[str, str, str]]:
    """Derive ``(ecosystem, name, version)`` from a wheel/sdist/tarball file name."""
    lower = filename.lower()
    if lower.endswith(".whl"):
        parts = filename[:-4].split("-")
        if len(parts) >= 5:
            return "pypi", parts[0], parts[1]
        return None
    for ext in _SDIST_EXTS:
        if lower.endswith(ext):
            stem = filename[: -len(ext)]
            if "-" not in stem:
                return None
            name, version = stem.rsplit("-", 1)
            if not version[:1].isdigit():
                return None
            eco = {".tgz": "npm", ".crate": "crates"}.get(ext, "pypi")
            return eco, name, version
    return None


def _env_label(path: str) -> str:
    parts = path.split(os.sep)
    for i in range(len(parts) - 1, -1, -1):
        if parts[i] in _SITE_DIRS:
            # <env>/lib/pythonX.Y/site-packages  or  <env>/Lib/site-packages
            cut = i - 1
            if cut >= 0 and parts[cut].lower().startswith("python"):
                cut -= 1
            if cut >= 0 and parts[cut].lower() in ("lib", "lib64"):
                cut -= 1
            return os.sep.join(parts[: cut + 1]) or os.sep
    return os.path.dirname(path)


def scan(
    feeds: List[Feed],
    roots: List[str],
    home: Optional[str] = None,
    host_checks: bool = True,
    log_files: Optional[Iterable[str]] = None,
    progress: Optional[Callable[[int], None]] = None,
) -> ScanResult:
    home = home or os.path.expanduser("~")
    matcher = _Matcher(feeds)
    stats = ScanStats(roots=list(roots))
    findings: List[Finding] = []
    seen_dirs: Set[Tuple[int, int]] = set()
    env_hits: Dict[str, List[Finding]] = {}
    ioc_files_by_env: Dict[str, List[Finding]] = {}

    def add(f: Finding) -> None:
        findings.append(f)

    def package_finding(
        kind: str,
        ecosystem: str,
        name: str,
        version: str,
        path: str,
        when: Optional[datetime] = None,
    ) -> None:
        for feed, ioc in matcher.match(ecosystem, name, version):
            timing = _timing(feed, when) if kind in ("installed", "node_modules") else ""
            severity = {"installed": "high", "node_modules": "high"}.get(kind, "medium")
            verb = {
                "installed": "is INSTALLED",
                "node_modules": "is INSTALLED in node_modules",
                "lockfile": "is pinned in a lockfile (next install would pull it)",
                "cache": "is present in a package cache (could be reinstalled offline)",
            }[kind]
            detail = ioc.note
            if timing == "inside-window":
                detail = (
                    detail + " Installed inside the live window."
                    if detail
                    else "Installed inside the live window."
                )
            elif timing == "before-upload":
                detail = (detail + " " if detail else "") + (
                    "Timestamp predates the malicious upload: probably copied or restored, "
                    "so verify with the file hashes."
                )
            f = Finding(
                advisory=feed.id,
                kind=kind,
                severity=severity,
                summary=f"{name}=={version} {verb}",
                path=path,
                ecosystem=ecosystem,
                package=ioc.name,
                version=version,
                installed_at=when,
                timing=timing,
                detail=detail.strip(),
            )
            add(f)
            if kind == "installed":
                env_hits.setdefault(_env_label(path), []).append(f)

    def ioc_file(path: str, name_lower: str) -> None:
        digest = _sha256(path)
        for feed, idx in matcher.file_names.get(name_lower, []):
            fioc = feed.files[idx]
            if digest and digest in fioc.sha256:
                f = Finding(
                    feed.id,
                    "ioc-file",
                    "critical",
                    f"{fioc.name} matches the known malicious SHA-256",
                    path,
                    detail=fioc.note,
                    installed_at=_birth_time(path),
                )
            elif fioc.distinctive:
                f = Finding(
                    feed.id,
                    "ioc-file",
                    "high",
                    f"{fioc.name} (distinctive IOC name) found in a Python environment",
                    path,
                    detail=(
                        "Hash does not match the feed, but this file name has no legitimate use. " + fioc.note
                    ).strip(),
                    installed_at=_birth_time(path),
                )
            elif fioc.sha256:
                continue  # common name (e.g. sitecustomize.py) with a different hash: not an IOC
            else:
                f = Finding(
                    feed.id,
                    "ioc-file",
                    "medium",
                    f"{fioc.name} present (feed has no hash to confirm)",
                    path,
                    detail=fioc.note,
                    installed_at=_birth_time(path),
                )
            add(f)
            ioc_files_by_env.setdefault(_env_label(path), []).append(f)

    for root in roots:
        root = os.path.abspath(os.path.expanduser(root))
        if not os.path.isdir(root):
            stats.errors += 1
            continue
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False, onerror=lambda e: None):
            try:
                st = os.stat(dirpath)
                key = (st.st_dev, st.st_ino)
                if key in seen_dirs:
                    dirnames[:] = []
                    continue
                seen_dirs.add(key)
            except OSError:
                stats.errors += 1
                continue
            stats.dirs += 1
            if progress and stats.dirs % 2000 == 0:
                progress(stats.dirs)

            if dirpath == os.path.join(home, "Library"):
                dirnames[:] = [d for d in dirnames if d == "Caches"]
            dist_dirs = [d for d in dirnames if d.endswith((".dist-info", ".egg-info"))]
            dirnames[:] = [
                d
                for d in dirnames
                if d not in PRUNE_DIRS and not d.endswith(PRUNE_SUFFIXES) and d not in dist_dirs
            ]

            for d in dist_dirs:
                pin = _read_dist_metadata(dirpath, d)
                if pin:
                    stats.packages_seen += 1
                    full = os.path.join(dirpath, d)
                    in_cache = any("cache" in part.lower() for part in full.split(os.sep))
                    kind = (
                        "cache" if in_cache and os.path.basename(dirpath) not in _SITE_DIRS else "installed"
                    )
                    marker = os.path.join(full, "RECORD")
                    when = _birth_time(marker if os.path.exists(marker) else full)
                    package_finding(kind, "pypi", pin[0], pin[1], full, when)

            in_site = os.path.basename(dirpath) in _SITE_DIRS
            in_npm_cache = "_cacache" in dirpath.split(os.sep) and "index-v5" in dirpath.split(os.sep)
            for fname in filenames:
                stats.files += 1
                full = os.path.join(dirpath, fname)
                lower = fname.lower()

                if in_site and lower in matcher.file_names:
                    ioc_file(full, lower)

                if fname == "package.json" and "node_modules" in dirpath.split(os.sep):
                    text = _read_text(full, 2 * 1024 * 1024)
                    if text:
                        try:
                            meta = json.loads(text)
                            name, version = meta.get("name"), meta.get("version")
                        except (json.JSONDecodeError, AttributeError):
                            name = version = None
                        if isinstance(name, str) and isinstance(version, str):
                            stats.packages_seen += 1
                            package_finding("node_modules", "npm", name, version, dirpath, _birth_time(full))
                    continue

                if parser_for(fname) is not None:
                    text = _read_text(full, MAX_LOCKFILE_BYTES)
                    if text is not None:
                        stats.lockfiles += 1
                        for eco, name, version in parse_lockfile(fname, text):
                            package_finding("lockfile", eco, name, version, full)
                    continue

                if in_npm_cache:
                    text = _read_text(full, 4 * 1024 * 1024)
                    if text:
                        for name, version in set(_NPM_CACHE_RE.findall(text)):
                            package_finding("cache", "npm", name, version, full)
                    continue

                art = _artifact_pin(fname)
                if art:
                    package_finding("cache", art[0], art[1], art[2], full)

    # Correlate IOC files with installs of the same advisory in the same environment.
    for env, files in ioc_files_by_env.items():
        for f in files:
            if f.severity != "critical" and any(h.advisory == f.advisory for h in env_hits.get(env, [])):
                f.severity = "critical"
                f.detail = (
                    f.detail + " Same environment also has the compromised release installed."
                ).strip()

    if host_checks:
        findings.extend(_host_findings(feeds, home, log_files))

    wanted: List[str] = []
    for feed in feeds:
        if any(f.advisory == feed.id and f.severity in ("high", "critical") for f in findings):
            for cls in feed.steals:
                if cls not in wanted:
                    wanted.append(cls)
    found, unlocated = creds.locate(home, wanted) if wanted else ({}, [])
    # Classes the file scan cannot enumerate are still part of the checklist.
    unlocated = [c for c in unlocated if c in creds.UNLOCATABLE] + [
        c for c in wanted if c not in creds.CREDENTIAL_LOCATIONS and c not in creds.UNLOCATABLE
    ]
    unlocated = list(dict.fromkeys(unlocated))

    findings.sort(key=lambda f: (-severity_rank(f.severity), f.path))
    return ScanResult(findings, stats, found, unlocated, feeds)


def _host_findings(feeds: List[Feed], home: str, log_files: Optional[Iterable[str]]) -> List[Finding]:
    out: List[Finding] = []
    for feed in feeds:
        for pattern in feed.host_artifacts:
            for match in sorted(glob.glob(os.path.expanduser(pattern))):
                out.append(
                    Finding(
                        feed.id,
                        "host-artifact",
                        "critical",
                        "Host artifact left by the malware exists",
                        match,
                        installed_at=_birth_time(match),
                        detail="This path is listed as an indicator of execution, not just installation.",
                    )
                )
    domains = {d for feed in feeds for d in feed.domains}
    if domains:
        candidates = [os.path.join(home, n) for n in (".zsh_history", ".bash_history")]
        candidates += list(log_files or [])
        for path in candidates:
            hits = _grep_domains(path, domains)
            for domain, line_no in hits:
                owner = next(f.id for f in feeds if domain in f.domains)
                out.append(
                    Finding(
                        owner,
                        "domain",
                        "high",
                        f"IOC domain {domain} appears in {os.path.basename(path)}",
                        path,
                        detail=f"First match on line {line_no}. Check proxy/DNS logs for actual traffic.",
                    )
                )
    return out


def _grep_domains(path: str, domains: Set[str]) -> List[Tuple[str, int]]:
    try:
        if not os.path.isfile(path) or os.path.getsize(path) > MAX_TEXT_BYTES:
            return []
        first: Dict[str, int] = {}
        with open(path, encoding="utf-8", errors="replace") as fh:
            for n, line in enumerate(fh, 1):
                low = line.lower()
                for d in domains:
                    if d not in first and d in low:
                        first[d] = n
        return sorted(first.items())
    except OSError:
        return []
