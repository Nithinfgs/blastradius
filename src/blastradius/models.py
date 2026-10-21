"""Result types shared by the scanner and the reporters."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

SEVERITIES = ("info", "low", "medium", "high", "critical")


def severity_rank(severity: str) -> int:
    return SEVERITIES.index(severity)


@dataclass
class Finding:
    advisory: str
    kind: str  # installed | lockfile | cache | node_modules | ioc-file | host-artifact | domain
    severity: str
    summary: str
    path: str
    ecosystem: str = ""
    package: str = ""
    version: str = ""
    installed_at: Optional[datetime] = None
    timing: str = ""  # inside-window | after-pull | before-upload | unknown | ""
    detail: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "advisory": self.advisory,
            "kind": self.kind,
            "severity": self.severity,
            "summary": self.summary,
            "path": self.path,
            "ecosystem": self.ecosystem,
            "package": self.package,
            "version": self.version,
            "installed_at": self.installed_at.isoformat() if self.installed_at else None,
            "timing": self.timing,
            "detail": self.detail,
        }


@dataclass
class ScanStats:
    roots: List[str] = field(default_factory=list)
    dirs: int = 0
    files: int = 0
    packages_seen: int = 0
    lockfiles: int = 0
    errors: int = 0


@dataclass
class ScanResult:
    findings: List[Finding]
    stats: ScanStats
    credentials: Dict[str, List[str]]  # credential class -> existing paths (never contents)
    credential_classes_unlocated: List[str]
    feeds: List[Any]

    def max_severity(self) -> Optional[str]:
        if not self.findings:
            return None
        return max((f.severity for f in self.findings), key=severity_rank)
