# Advisory feed format

A feed is one JSON object describing one incident. Validate with `blastradius validate FILE`.

| Field | Type | Required | Meaning |
|---|---|---|---|
| `id` | string | yes | Letters, digits, `.`, `_`, `-`. Used in reports. |
| `title` | string | yes | One-line description. |
| `source` | string | no | URL of the primary write-up. |
| `window.start` / `window.end` | ISO-8601 | no | When the malicious release was live. Installs before `start` are flagged `before-upload`, after `end` are `after-pull`. Naive timestamps are treated as UTC. |
| `packages[]` | list | yes | See below. |
| `files[]` | list | no | IOC file names and hashes. |
| `host_artifacts[]` | list of globs | no | Paths the malware creates, e.g. `/tmp/.pc_once_*`. `~` is expanded. |
| `domains[]` | list | no | Lower-case hostnames searched for in shell history and `--logs` files. |
| `steals[]` | list | no | Credential classes at risk. Known classes are located on disk (`ssh`, `aws`, `azure`, `gcp`, `kubernetes`, `docker`, `github-cli`, `git-credentials`, `npm`, `pypi`, `cargo`, `gpg`, `netrc`, `terraform`, `ai-tools`); others (`browser`, `ci`, `env`, `cloud-instance`, `llm-provider-keys`, `tls`) are listed as manual items. |
| `remediation[]` | list | no | Steps printed under "What to do". |
| `caveats[]` | list | no | Printed at the end of the report. Use it to state how reliable the IOCs are. |

## `packages[]`

| Field | Meaning |
|---|---|
| `ecosystem` | `pypi`, `npm`, `crates` or `go` |
| `name` | Package name (normalised per ecosystem: PEP 503 for PyPI, lower-case otherwise) |
| `versions` | Exact bad versions |
| `ranges` | Comma-separated clauses with `>=`, `<=`, `>`, `<`, `==`, `!=`, e.g. `>=1.82.7,<1.83` |
| `note` | Shown with each finding |

At least one of `versions` or `ranges` is required.

## `files[]`

| Field | Meaning |
|---|---|
| `name` | File name (case-insensitive), matched only inside `site-packages` / `dist-packages` |
| `sha256` | Known-bad digests. A match is `critical`. |
| `distinctive` | `true` when the name has no legitimate use (such as `cook.pth`): a name match without a hash match is then `high`. When `false` and `sha256` is given, a non-matching file is ignored (for common names such as `sitecustomize.py`). |
| `note` | Shown with the finding |

An IOC file whose environment also contains a compromised package from the same feed is always escalated to `critical`.
