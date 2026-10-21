"""Small, dependency-free version comparison and name normalisation.

This is deliberately not a full PEP 440 / semver implementation. It orders the
common shapes (``1.2.3``, ``1.2.3rc1``, ``1.2.3.post1``, ``1.2.3.dev4``,
``1.2.3-beta.2``) well enough to evaluate advisory ranges such as
``>=1.82.7,<1.83``. Versions it cannot parse never match a range.
"""

from __future__ import annotations

import re
from typing import Optional, Tuple

_VERSION_RE = re.compile(
    r"""^v?(?P<release>\d+(?:\.\d+)*)
        (?:[.\-_]?(?P<pre>alpha|beta|preview|pre|rc|a|b|c)[.\-_]?(?P<pre_n>\d+)?)?
        (?:[.\-_]?post[.\-_]?(?P<post>\d+)?)?
        (?:[.\-_]?dev[.\-_]?(?P<dev>\d+)?)?
        (?:\+[A-Za-z0-9.\-_]+)?$""",
    re.VERBOSE | re.IGNORECASE,
)

_PRE_RANK = {
    "a": -3,
    "alpha": -3,
    "b": -2,
    "beta": -2,
    "c": -1,
    "rc": -1,
    "pre": -1,
    "preview": -1,
}

VersionKey = Tuple[Tuple[int, ...], int, int, int, int]


def normalize_name(ecosystem: str, name: str) -> str:
    """Normalise a package name so feed entries and scan results compare equal."""
    name = name.strip()
    if ecosystem == "pypi":
        return re.sub(r"[-_.]+", "-", name).lower()
    return name.lower()


def parse_version(text: str) -> Optional[VersionKey]:
    match = _VERSION_RE.match(text.strip())
    if not match:
        return None
    release = tuple(int(p) for p in match.group("release").split("."))
    while len(release) > 1 and release[-1] == 0:
        release = release[:-1]
    pre = match.group("pre")
    if pre:
        pre_rank, pre_n = _PRE_RANK[pre.lower()], int(match.group("pre_n") or 0)
    else:
        pre_rank, pre_n = 0, 0
    dev = match.group("dev")
    if dev is not None and not pre:
        pre_rank = -4  # a bare .devN sorts before alphas of the same release
    post = int(match.group("post") or 0) if "post" in text.lower() else 0
    dev_n = int(dev or 0) if dev is not None else 10**9
    return (release, pre_rank, pre_n, post, dev_n)


def versions_equal(a: str, b: str) -> bool:
    ka, kb = parse_version(a), parse_version(b)
    if ka is not None and kb is not None:
        return ka == kb
    return a.strip().lstrip("v").lower() == b.strip().lstrip("v").lower()


_CLAUSE_RE = re.compile(r"^(>=|<=|==|!=|>|<)\s*(\S+)$")


def validate_range(spec: str) -> Optional[str]:
    """Return an error message for a malformed range spec, or ``None`` if valid."""
    clauses = [c.strip() for c in spec.split(",") if c.strip()]
    if not clauses:
        return "empty range"
    for clause in clauses:
        m = _CLAUSE_RE.match(clause)
        if not m:
            return f"cannot parse clause {clause!r}"
        if parse_version(m.group(2)) is None:
            return f"cannot parse version in clause {clause!r}"
    return None


def in_range(version: str, spec: str) -> bool:
    """True if ``version`` satisfies every comma-separated clause in ``spec``."""
    key = parse_version(version)
    if key is None:
        return False
    for clause in (c.strip() for c in spec.split(",") if c.strip()):
        m = _CLAUSE_RE.match(clause)
        if not m:
            return False
        bound = parse_version(m.group(2))
        if bound is None:
            return False
        op = m.group(1)
        ok = {
            ">=": key >= bound,
            "<=": key <= bound,
            ">": key > bound,
            "<": key < bound,
            "==": key == bound,
            "!=": key != bound,
        }[op]
        if not ok:
            return False
    return True
