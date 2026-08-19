from typing import Any, Dict, List

from .hunter import match_event


def evaluate_hunting(events: List[Dict[str, Any]], technique_id: str) -> Dict[str, Any]:
    """Evaluate against optional labels in normalized events.

    Ground truth can be supplied using:
      - label / ground_truth / is_malicious = boolean-ish
      - and optionally attack_technique / TechniqueId.
    If a malicious event is tagged with another ATT&CK technique, it is treated as
    negative for the technique currently being benchmarked.
    """
    tp = fp = tn = fn = 0
    usable = 0
    rows = []

    for i, event in enumerate(events):
        if event.get("label") is None and not event.get("attack_technique"):
            continue
        usable += 1
        gt = bool(event.get("label"))
        tagged_raw = event.get("attack_technique")
        if isinstance(tagged_raw, (list, tuple, set)):
            tagged = {str(x).upper().strip() for x in tagged_raw if str(x).strip()}
        else:
            tagged_text = str(tagged_raw or "").replace(";", ",")
            tagged = {x.upper().strip() for x in tagged_text.split(",") if x.strip()}
        if tagged:
            gt = gt and technique_id.upper() in tagged

        pred, reasons, score = match_event(event, technique_id)
        if pred and gt:
            tp += 1
        elif pred and not gt:
            fp += 1
        elif not pred and gt:
            fn += 1
        else:
            tn += 1
        rows.append({"event_index": i, "ground_truth": gt, "predicted": pred, "score": score, "reasons": reasons})

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0

    return {
        "technique_id": technique_id,
        "labeled_events": usable,
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "false_positive_rate": round(fpr, 4),
        "details": rows,
    }
