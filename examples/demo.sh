#!/usr/bin/env bash
# End-to-end demo: build a synthetic "compromised" machine in a temp dir and scan it.
# Everything created here is benign test data; nothing outside the temp dir is touched.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
PY="${PYTHON:-python3}"
DEMO="$(mktemp -d)"
trap 'rm -rf "$DEMO"' EXIT

SITE="$DEMO/home/work/api/.venv/lib/python3.12/site-packages"
mkdir -p "$SITE/litellm-1.107.0.dist-info" "$DEMO/home/work/api" "$DEMO/home/.ssh"
printf 'Metadata-Version: 2.1\nName: litellm\nVersion: 1.107.0\n' > "$SITE/litellm-1.107.0.dist-info/METADATA"
: > "$SITE/litellm-1.107.0.dist-info/RECORD"
echo "import cook  # benign demo fixture" > "$SITE/cook.pth"
echo "litellm==1.107.0" > "$DEMO/home/work/api/requirements.txt"
echo "demo-not-a-real-key" > "$DEMO/home/.ssh/id_ed25519"

echo "== scan of the synthetic machine (expect findings, exit 1) =="
set +e
HOME="$DEMO/home" PYTHONPATH="$HERE/../src" "$PY" -m blastradius scan \
  --root "$DEMO/home" --no-color --quiet
status=$?
set -e
echo "exit status: $status"
[ "$status" -eq 1 ]

echo
echo "== scan of a clean directory (expect exit 0) =="
mkdir -p "$DEMO/clean"
PYTHONPATH="$HERE/../src" "$PY" -m blastradius scan --root "$DEMO/clean" --no-host-checks --quiet
