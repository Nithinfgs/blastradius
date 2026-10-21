"""Locate (never read) credential stores so a rotation checklist can be scoped.

Only ``os.path`` existence checks are performed. File contents are never opened.
"""

from __future__ import annotations

import glob
import os
from typing import Dict, List, Tuple

# credential class -> glob patterns relative to the home directory
CREDENTIAL_LOCATIONS: Dict[str, Tuple[str, ...]] = {
    "ssh": (".ssh/id_*", ".ssh/*.pem", ".ssh/config"),
    "aws": (".aws/credentials", ".aws/config", ".aws/sso/cache"),
    "azure": (".azure/accessTokens.json", ".azure/msal_token_cache.*", ".azure/azureProfile.json"),
    "gcp": (".config/gcloud/credentials.db", ".config/gcloud/application_default_credentials.json"),
    "kubernetes": (".kube/config",),
    "docker": (".docker/config.json",),
    "github-cli": (".config/gh/hosts.yml",),
    "git-credentials": (".git-credentials",),
    "npm": (".npmrc",),
    "pypi": (".pypirc",),
    "cargo": (".cargo/credentials.toml", ".cargo/credentials"),
    "gpg": (".gnupg/private-keys-v1.d", ".gnupg/secring.gpg"),
    "netrc": (".netrc",),
    "terraform": (".terraform.d/credentials.tfrc.json",),
    "ai-tools": (
        ".claude.json",
        ".claude/.credentials.json",
        ".config/openai",
        ".codex/auth.json",
        ".config/github-copilot",
    ),
}

# classes that live in places a file scan cannot enumerate
UNLOCATABLE = {
    "browser": "browser-saved passwords, cookies and history",
    "ci": "CI/CD secrets stored in your CI provider",
    "env": "secrets exported as environment variables in shells, dotfiles or .env files",
    "cloud-instance": "cloud instance-role credentials (check cloud audit logs)",
    "llm-provider-keys": "LLM provider API keys held in application databases or config",
    "tls": "TLS private keys on disk or in secret managers",
}


def locate(home: str, classes: List[str]) -> Tuple[Dict[str, List[str]], List[str]]:
    """Return ``(found, unlocated)`` for the requested credential classes."""
    found: Dict[str, List[str]] = {}
    unlocated: List[str] = []
    for cls in classes:
        patterns = CREDENTIAL_LOCATIONS.get(cls)
        if patterns is None:
            unlocated.append(cls)
            continue
        hits: List[str] = []
        for pattern in patterns:
            for match in sorted(glob.glob(os.path.join(home, pattern))):
                if match.endswith(".pub"):
                    continue
                hits.append(match)
        if hits:
            found[cls] = hits
    return found, unlocated
