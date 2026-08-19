import json
import os
from typing import Any, Dict, Optional

from .evaluation import evaluate_hunting
from .hunter import hunt_events
from .log_loader import load_events
from .plan import build_hunting_plan


def run_hunting_pipeline(
    cti_result: Dict[str, Any],
    log_path: str,
    output_path: Optional[str] = None,
    evaluate: bool = True,
) -> Dict[str, Any]:
    """Run Phase 3 end-to-end using Phase 2 CTI result + Windows/Sysmon logs."""
    plan = build_hunting_plan(cti_result)
    technique_id = plan["technique_id"]
    events = load_events(log_path)
    findings = hunt_events(events, technique_id) if plan.get("supported") else []

    result = {
        "cti_input": {
            "technique_id": cti_result.get("technique_id"),
            "technique_name": cti_result.get("technique_name"),
            "evidence": cti_result.get("evidence"),
            "iocs": cti_result.get("iocs", {}),
        },
        "hunting_plan": plan,
        "log_source": os.path.basename(log_path),
        "events_scanned": len(events),
        "matched_events": len(findings),
        "findings": findings,
    }
    if evaluate:
        result["evaluation"] = evaluate_hunting(events, technique_id)

    if output_path:
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=2)
    return result
