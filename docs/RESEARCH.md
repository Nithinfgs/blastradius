# Research notes and project selection

Research date: **2026-10-21**. Metrics were read from the pages and API calls listed below on that date. Star counts on GitHub can be inflated or volatile, so treat them as a rough signal of attention, not of quality.

## Sources and observations

| Source | URL | What was observed (2026-10-21) |
|---|---|---|
| GitHub Trending, weekly | https://github.com/trending?since=weekly | 16 repos, dominated by coding-agent tooling (opencode 219k stars, orca 100k, context-mode 31k +3.5k/week, ai-memory 12k +2.6k/week, claude-plugins-official +5.6k/week), plus reverse engineering (ghidra) and voice tools |
| GitHub Trending, daily | https://github.com/trending?since=daily | 12 repos: cloudflare/security-audit-skill (+2.0k today), headroom (context compression), graphify, ponytail, vllm, ComfyUI, supabase, twenty, Kronos, freehire |
| GitHub Search API (created after 2026-09-20, >300 stars) | https://api.github.com/search/repositories | Fast risers are mostly "from scratch in Rust" office apps (storytold/*craft), free-model wrappers and Android/TV tools; several look like star-inflated or hype-driven projects |
| Hacker News front page | https://hn.algolia.com/api/v1/search?tags=front_page | "Compromised LiteLLM 1.107.0 on PyPI installs a credential stealer and backdoor" (205 points), "PHP2Shell: AI uncovers critical RCE in PHP" (397), PHP 8.2.35 security release (796), DuckDB 2.0 LTS (244) |
| SafeDep incident write-up | https://safedep.io/litellm-pypi-compromise-credential-stealer-backdoor/ | Full IOC set for litellm 1.107.0: affected version, 2026-10-21 11:39 UTC upload, ~13:40 UTC removal, file names, SHA-256 hashes, host artifacts, domains, credential classes targeted |
| Web search, 2026 supply-chain incidents | https://thehackernews.com/2026/02/compromised-dydx-npm-and-pypi-packages.html , https://www.theregister.com/2026/04/30/supply_chain_attacks_sap_npm_packages/ | dYdX npm+PyPI compromise (Feb), LiteLLM 1.82.7/1.82.8 (Mar), SAP/Intercom Shai-Hulud-style npm worm (Apr), larger Shai-Hulud wave (May, lower-quality source). A new incident roughly every month |
| Reddit | https://www.reddit.com/r/programming | Not fetchable from this environment (blocked); no Reddit evidence is claimed |
| Product Hunt | https://www.producthunt.com | Not queried; no Product Hunt evidence is claimed |

## Repositories examined (28)

From the trending pages above: morluto/rea, anthropics/claude-plugins-official, K-Dense-AI/scientific-agent-skills, ruvnet/ruflo, android/skills, NationalSecurityAgency/ghidra, debpalash/VoiceStudio, mksglu/context-mode, heygen-com/hyperframes, cursor/plugins, HKUDS/CLI-Anything, akitaonrails/ai-memory, anomalyco/opencode, wshobson/agents, earthtojake/text-to-cad, stablyai/orca, cloudflare/security-audit-skill, vllm-project/vllm, headroomlabs-ai/headroom, DietrichGebert/ponytail, Comfy-Org/ComfyUI, supabase/supabase, twentyhq/twenty, shiyu-coder/Kronos, strelov1/freehire, Graphify-Labs/graphify, plus the fast risers from the search API (storytold/photocraft, yetone/magpie).

## Trend read

- **Short-lived hype:** one-click free-model wrappers, "reimplement X in pure Rust" mass-produced repos.
- **Strong momentum, crowded:** coding-agent harnesses, plugins/skills, memory and context compression. The author's account and the other agents on this machine already cover this space heavily (token audits, instruction-file linting, session forensics), so another tool there would be a duplicate.
- **Persistent pain with a live trigger:** supply-chain compromises of popular packages. Today's litellm 1.107.0 incident is the 4th+ major registry compromise this year. Defenders' first question after every one is the same: *"Did this reach any machine of mine, when, and what must I rotate?"*

## Opportunities scored

Weights: demand 25%, differentiation 20%, feasibility 20%, usefulness 20%, testability 15%. Scores 1-5.

| # | Opportunity | Demand | Differ. | Feasib. | Useful | Testab. | Weighted |
|---|---|---|---|---|---|---|---|
| 1 | **Incident exposure sweeper**: given a machine-readable IOC feed, find every install, lockfile pin, cache entry, IOC file and host artifact on a dev machine, with install timing and a rotation checklist scoped to credentials that actually exist | 5 | 4 | 5 | 5 | 5 | **4.80** |
| 2 | Free-threaded Python (3.14t) compatibility checker for a dependency tree | 3 | 4 | 4 | 3 | 4 | 3.55 |
| 3 | Parquet/CSV schema + row diff using DuckDB 2.0 for data contracts | 3 | 2 | 4 | 4 | 4 | 3.35 |
| 4 | Agent transcript token/cost analyzer (another one) | 4 | 1 | 5 | 3 | 5 | 3.55 |
| 5 | Local LLM server health/benchmark dashboard | 3 | 2 | 3 | 3 | 3 | 2.80 |

Closest existing tools for #1 and how it differs:
- OSV-Scanner / pip-audit / `npm audit`: match lockfiles against advisory databases, forward-looking, no machine-wide sweep of venvs and caches, no install-time evidence, no IOC file hashing, and they lag hours behind a fresh incident.
- Safety/Socket/SafeDep scanners: hosted or per-project; they do not answer "which of the 40 virtualenvs on this laptop got it".
- Hand-run `grep`/`pip freeze` from the incident blog post: what people do today. This project turns that into a repeatable, feed-driven tool.

## Decision

Build **blastradius**, option #1.

1. **Name:** blastradius
2. **Problem:** after a package compromise, determine your real exposure fast, offline, with evidence.
3. **Users:** developers, platform/security engineers, anyone with many virtualenvs and `node_modules` trees.
4. **Why now:** litellm 1.107.0 was published and pulled within about two hours on 2026-10-21; machines that installed in that window may already have run a credential stealer.
5. **Evidence:** see the table above (HN, SafeDep, trending security-audit interest).
6. **Difference:** feed-driven (a new incident is a JSON file, not a code change); sweeps installed packages, lockfiles, package caches and `node_modules`; hashes IOC files; reports install time against the live window; produces a rotation checklist limited to credential locations present on the machine; never reads secret contents; zero runtime dependencies.
7. **Features:** see README.
8. **Stack:** Python 3.9+ standard library only. Dev: pytest, ruff, mypy.
9. **Testing:** unit tests for version matching, feed validation and each lockfile parser; integration tests that build synthetic environments in temp dirs and run the real CLI; an end-to-end demo script.
10. **Acceptance:** scanning a synthetic machine containing a compromised install, lockfile pin, cache artifact and IOC file reports each with the right severity, exit code 1, and a clean machine exits 0; JSON output parses; no file contents of credential files are read.
