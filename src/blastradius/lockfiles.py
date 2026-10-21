"""Extract ``(ecosystem, name, version)`` pins from common lockfile formats.

Parsers are regex/JSON based, tolerant of malformed input, and never execute
anything. They return every pin they can find rather than failing the scan.
"""

from __future__ import annotations

import json
import re
from typing import Callable, Dict, Iterator, Optional, Tuple

Pin = Tuple[str, str, str]  # ecosystem, name, version

_REQ_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*===?\s*([^\s;\\#,]+)", re.MULTILINE)
_TOML_PKG_RE = re.compile(r'\[\[package\]\]\s*\r?\nname\s*=\s*"([^"]+)"\s*\r?\nversion\s*=\s*"([^"]+)"')
_YARN_HEADER_RE = re.compile(r"^(?P<h>[^\s#][^\n]*):\s*$", re.MULTILINE)
_YARN_VERSION_RE = re.compile(r'^\s+version:?\s+"?([^"\s]+)"?\s*$', re.MULTILINE)
_PNPM_RE = re.compile(r"^  '?/?(@?[^@'\s]+?)[@/](\d[\w.\-+]*)(?:\([^)]*\))*'?:\s*$", re.MULTILINE)
_GO_SUM_RE = re.compile(r"^(\S+) v([^\s/]+?)(?:/go\.mod)? h1:", re.MULTILINE)


def parse_requirements(text: str) -> Iterator[Pin]:
    for name, version in _REQ_RE.findall(text):
        yield "pypi", name, version


def _parse_toml_packages(ecosystem: str) -> Callable[[str], Iterator[Pin]]:
    def parse(text: str) -> Iterator[Pin]:
        for name, version in _TOML_PKG_RE.findall(text):
            yield ecosystem, name, version

    return parse


def parse_pipfile_lock(text: str) -> Iterator[Pin]:
    data = json.loads(text)
    for section in ("default", "develop"):
        for name, meta in (data.get(section) or {}).items():
            version = meta.get("version", "") if isinstance(meta, dict) else ""
            if version.startswith("=="):
                yield "pypi", name, version[2:]


def parse_package_lock(text: str) -> Iterator[Pin]:
    data = json.loads(text)
    packages = data.get("packages")
    if isinstance(packages, dict):
        for key, meta in packages.items():
            if "node_modules/" not in key or not isinstance(meta, dict):
                continue
            version = meta.get("version")
            if isinstance(version, str):
                yield "npm", key.rsplit("node_modules/", 1)[1], version

    def walk(deps: Dict[str, object]) -> Iterator[Pin]:
        for name, meta in deps.items():
            if not isinstance(meta, dict):
                continue
            version = meta.get("version")
            if isinstance(version, str) and not version.startswith(("file:", "git", "http", "npm:")):
                yield "npm", name, version
            nested = meta.get("dependencies")
            if isinstance(nested, dict):
                yield from walk(nested)

    legacy = data.get("dependencies")
    if isinstance(legacy, dict):
        yield from walk(legacy)


def _yarn_name(spec: str) -> Optional[str]:
    spec = spec.split(",")[0].strip().strip('"')
    idx = spec.find("@", 1) if spec.startswith("@") else spec.find("@")
    return spec[:idx] if idx > 0 else None


def parse_yarn_lock(text: str) -> Iterator[Pin]:
    headers = list(_YARN_HEADER_RE.finditer(text))
    for i, header in enumerate(headers):
        name = _yarn_name(header.group("h"))
        if not name:
            continue
        end = headers[i + 1].start() if i + 1 < len(headers) else len(text)
        version = _YARN_VERSION_RE.search(text[header.end() : end])
        if version:
            yield "npm", name, version.group(1)


def parse_pnpm_lock(text: str) -> Iterator[Pin]:
    for name, version in _PNPM_RE.findall(text):
        yield "npm", name, version


def parse_go_sum(text: str) -> Iterator[Pin]:
    for module, version in _GO_SUM_RE.findall(text):
        yield "go", module, version


_BY_NAME: Dict[str, Callable[[str], Iterator[Pin]]] = {
    "uv.lock": _parse_toml_packages("pypi"),
    "poetry.lock": _parse_toml_packages("pypi"),
    "pdm.lock": _parse_toml_packages("pypi"),
    "cargo.lock": _parse_toml_packages("crates"),
    "pipfile.lock": parse_pipfile_lock,
    "package-lock.json": parse_package_lock,
    "npm-shrinkwrap.json": parse_package_lock,
    "yarn.lock": parse_yarn_lock,
    "pnpm-lock.yaml": parse_pnpm_lock,
    "go.sum": parse_go_sum,
}


def parser_for(filename: str) -> Optional[Callable[[str], Iterator[Pin]]]:
    lower = filename.lower()
    if lower in _BY_NAME:
        return _BY_NAME[lower]
    if lower.endswith(".txt") and (lower.startswith(("requirements", "constraints"))):
        return parse_requirements
    return None


def parse_lockfile(filename: str, text: str) -> Iterator[Pin]:
    """Yield pins for a known lockfile; malformed JSON yields nothing."""
    parser = parser_for(filename)
    if parser is None:
        return
    try:
        yield from parser(text)
    except (json.JSONDecodeError, AttributeError, TypeError):
        return
