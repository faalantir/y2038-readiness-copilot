# Y2038 Readiness Copilot

A compact engineering prototype that scans source code, database schemas, API contracts, message definitions, build files, and device manifests for **potential Year 2038 / timestamp-width risks**.

The tool does not claim that every finding is a confirmed vulnerability. It creates a review queue that can be validated with dataflow analysis, platform context, and runtime tests.

## Workflow

1. Static rules identify suspicious timestamp-width patterns.
2. Findings are ranked with severity and confidence.
3. Reports include rationale, suggested fixes, and future-date test ideas.
4. The generated triage prompt can be reviewed by an LLM or by a human reviewer to classify findings and reduce noise.

## Capabilities

- Python CLI scanner
- static-analysis style rules
- JSON, Markdown, and SARIF output
- support for C/C++, SQL, protobuf, ROS/DDS-style messages, JSON/OpenAPI/YAML, build files, and device manifests
- optional AI-assisted triage prompt for review and remediation planning

## Quick start

```bash
python3 --version
cd y2038-readiness-copilot
python3 -m venv .venv
source .venv/bin/activate
python -m y2038_copilot.scan samples --repo-name sample --out reports/sample
```

Open:

```bash
cat reports/sample/report.md
cat reports/sample/ai_triage_prompt.md
```

The scanner writes:

```text
reports/sample/findings.json
reports/sample/report.md
reports/sample/results.sarif
reports/sample/ai_triage_prompt.md
```

## Run against public GitHub repositories

```bash
bash scripts/clone_reference_repos.sh
bash scripts/scan_reference_repos.sh
```

Then open:

```bash
cat reports/cross_repo_summary.md
```

Reference repositories used by the script:

- `ros2/rcl_interfaces`
- `esphome/esphome`
- `eclipse-mosquitto/mosquitto`
- `dun/munge`

Optional larger embedded-framework scan:

```bash
# Edit scripts/clone_reference_repos.sh and scripts/scan_reference_repos.sh
# Uncomment esp-idf lines, then run:
bash scripts/clone_reference_repos.sh
bash scripts/scan_reference_repos.sh
```

## Example CLI usage

Scan one path:

```bash
python -m y2038_copilot.scan path/to/repo --repo-name my-repo --out reports/my-repo
```

Limit findings while testing:

```bash
python -m y2038_copilot.scan path/to/repo --repo-name my-repo --out reports/my-repo --max-findings 100
```

Summarise multiple reports:

```bash
python -m y2038_copilot.summarize reports/*/findings.json --out reports/cross_repo_summary.md
```

## What the scanner looks for

| File type | Examples detected |
|---|---|
| C/C++ | `int32_t expiry_time`, `int event_time = time(NULL)`, casts from `time_t` to `int`, `sizeof(time_t)` serialization |
| SQL | `event_time INT`, `expires_at INTEGER`, `timestamp INT` |
| Protobuf | `fixed32 epoch_seconds`, `int32 expiry_timestamp` |
| ROS/DDS-style messages | `int32 sec` in time-related message definitions |
| JSON/OpenAPI/YAML | timestamp-like fields near `int32` / `integer` schemas |
| Build files | 32-bit target hints, `_TIME_BITS=64`, `_FILE_OFFSET_BITS=64` |
| Manifests | 32-bit architecture with lifecycle beyond 2038 |

## How the AI layer fits

The scanner is intentionally **rules-first, AI-second**.

The scanner produces structured findings. The triage prompt asks a reviewer or LLM to classify findings as:

- likely real risk;
- needs more context;
- likely false positive;
- positive control.

The goal is to reduce static-analysis noise and convert timestamp-risk signals into clear engineering actions.
