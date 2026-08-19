from typing import Any, Dict, Iterable, List, Tuple

from .knowledge import get_profile


def _s(value: Any) -> str:
    return "" if value is None else str(value).lower()


def _endswith_any(value: Any, suffixes: Iterable[str]) -> bool:
    v = _s(value).replace("/", "\\")
    return any(v.endswith(_s(x).replace("/", "\\")) for x in suffixes)


def _contains_any(text: str, terms: Iterable[str]) -> List[str]:
    hay = _s(text)
    return [term for term in terms if _s(term) in hay]


def _event_text(event: Dict[str, Any]) -> str:
    pieces = [
        event.get("command_line"), event.get("image"), event.get("parent_image"),
        event.get("target_image"), event.get("query_name"), event.get("task_name"),
        event.get("raw"),
    ]
    return " ".join(_s(x) for x in pieces if x is not None)


def match_event(event: Dict[str, Any], technique_id: str) -> Tuple[bool, List[str], int]:
    profile = get_profile(technique_id)
    if not profile:
        return False, ["Unsupported ATT&CK technique"], 0

    rule = profile.get("match", {})
    reasons: List[str] = []
    score = 0

    event_ids = rule.get("event_ids", [])
    if event_ids and event.get("event_id") in event_ids:
        score += 1
        reasons.append(f"event_id={event.get('event_id')}")

    if rule.get("image_endswith") and _endswith_any(event.get("image"), rule["image_endswith"]):
        score += 2
        reasons.append("suspicious process image")

    if rule.get("parent_image_endswith") and _endswith_any(event.get("parent_image"), rule["parent_image_endswith"]):
        score += 2
        reasons.append("suspicious parent process")

    if rule.get("target_image_endswith") and _endswith_any(event.get("target_image"), rule["target_image_endswith"]):
        score += 3
        reasons.append("sensitive target process")

    matched_terms = _contains_any(_event_text(event), rule.get("contains_any", []))
    if matched_terms:
        score += min(3, len(matched_terms))
        reasons.append("keywords=" + ", ".join(matched_terms[:5]))

    # Technique-specific minimum evidence. This intentionally favors precision.
    tid = technique_id.upper()
    if tid == "T1059.001":
        # PowerShell alone is common in administration. Require either a suspicious
        # PowerShell command keyword, or Script Block Logging with such a keyword.
        matched = (
            any("process image" in r for r in reasons) and bool(matched_terms)
        ) or (event.get("event_id") == 4104 and bool(matched_terms))
    elif tid == "T1053.005":
        matched = (event.get("event_id") in {4698, 106}) or (
            any("process image" in r for r in reasons) and bool(matched_terms)
        )
    elif tid == "T1003.001":
        matched = any("sensitive target process" in r for r in reasons) or (
            bool(matched_terms) and score >= 4
        )
    elif tid == "T1566.001":
        matched = any("suspicious parent process" in r for r in reasons) and any(
            "suspicious process image" in r for r in reasons
        )
    else:
        matched = score >= 4

    return matched, reasons, score


def hunt_events(events: List[Dict[str, Any]], technique_id: str) -> List[Dict[str, Any]]:
    findings = []
    for idx, event in enumerate(events):
        matched, reasons, score = match_event(event, technique_id)
        if matched:
            findings.append({
                "event_index": idx,
                "technique_id": technique_id,
                "risk_score": min(100, 35 + score * 10),
                "reasons": reasons,
                "event": {k: v for k, v in event.items() if k != "raw"},
            })
    return findings
