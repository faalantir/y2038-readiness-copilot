from __future__ import annotations

import argparse
from pathlib import Path

from .reporter import write_summary_from_json


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Summarise multiple Y2038 findings.json files into one public repo scan summary.")
    parser.add_argument("json_files", nargs="+", help="Paths to findings.json files")
    parser.add_argument("--out", default="reports/cross_repo_summary.md", help="Output Markdown path")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    json_paths = [Path(p) for p in args.json_files]
    write_summary_from_json(json_paths, Path(args.out))
    print(f"Wrote {args.out}")


if __name__ == "__main__":
    main()
