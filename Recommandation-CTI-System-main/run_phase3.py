#!/usr/bin/env python3
"""CLI demo for Phase 3 - Threat Hunting.

Example:
python run_phase3.py \
  --cti api_backend/mock_data/report_1.json \
  --logs hunting_lab/sample_logs/windows_sysmon_demo.jsonl \
  --output hunting_lab/output/report_1_hunting.json
"""

import argparse
import json

from threat_hunting.pipeline import run_hunting_pipeline


def main():
    p = argparse.ArgumentParser(description="Run ATT&CK-driven Threat Hunting pipeline")
    p.add_argument("--cti", required=True, help="Phase 2 CTI JSON result")
    p.add_argument("--logs", required=True, help="JSON/JSONL/CSV/EVTX Windows/Sysmon logs")
    p.add_argument("--output", default="hunting_lab/output/hunting_result.json")
    p.add_argument("--no-eval", action="store_true", help="Skip benchmark metrics")
    args = p.parse_args()

    with open(args.cti, "r", encoding="utf-8-sig") as f:
        cti = json.load(f)

    result = run_hunting_pipeline(cti, args.logs, args.output, evaluate=not args.no_eval)
    print(json.dumps({
        "technique_id": result["hunting_plan"]["technique_id"],
        "hypothesis": result["hunting_plan"]["hypothesis"],
        "events_scanned": result["events_scanned"],
        "matched_events": result["matched_events"],
        "evaluation": result.get("evaluation", {}),
        "output": args.output,
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
