#!/usr/bin/env bash
set -euo pipefail

mkdir -p reports

scan_repo() {
  local name="$1"
  if [ ! -d "repos/${name}" ]; then
    echo "Skipping ${name}: repos/${name} not found. Run scripts/clone_reference_repos.sh first."
    return 0
  fi
  echo "Scanning ${name}..."
  python -m y2038_copilot.scan "repos/${name}" --repo-name "$name" --out "reports/${name}" --max-findings 250
}

scan_repo rcl_interfaces
scan_repo esphome
scan_repo mosquitto
scan_repo munge
# scan_repo esp-idf

python -m y2038_copilot.summarize reports/*/findings.json --out reports/cross_repo_summary.md

echo "Done. Open reports/cross_repo_summary.md"
