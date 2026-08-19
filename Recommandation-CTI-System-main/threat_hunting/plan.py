import json
from datetime import datetime, timezone
from typing import Any, Dict

from .knowledge import get_profile


def _sigma_yaml(technique_id: str, profile: Dict[str, Any]) -> str:
    """Build a compact Sigma-compatible baseline rule as YAML text.

    The rule is intentionally conservative and portable. Field mapping is left to
    the Sigma backend / SIEM converter because real schemas differ by platform.
    """
    sigma = profile.get("sigma", {})
    logsource = profile.get("logsource", {})
    title = sigma.get("title", f"Hunting rule for {technique_id}")
    image_values = sigma.get("selection_image", [])
    parent_values = sigma.get("selection_parent", [])
    keywords = sigma.get("selection_keywords", [])

    lines = [
        f'title: "{title}"',
        "status: experimental",
        "description: \"Baseline hunting rule generated from CTI ATT&CK mapping.\"",
        "references:",
        f"  - https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/",
        "tags:",
        f"  - attack.{technique_id.lower()}",
        "logsource:",
    ]
    for k, v in logsource.items():
        lines.append(f"  {k}: {v}")

    lines.append("detection:")
    selections = []
    if image_values:
        selections.append("selection_image")
        lines += ["  selection_image:", "    Image|endswith:"] + [f"      - '{x}'" for x in image_values]
    if parent_values:
        selections.append("selection_parent")
        lines += ["  selection_parent:", "    ParentImage|endswith:"] + [f"      - '{x}'" for x in parent_values]
    if keywords:
        selections.append("selection_keywords")
        lines += ["  selection_keywords:", "    CommandLine|contains:"] + [f'      - "{x}"' for x in keywords]

    if "selection_parent" in selections and "selection_image" in selections:
        condition = "selection_parent and selection_image"
    elif "selection_image" in selections and "selection_keywords" in selections:
        # Detection-oriented baseline: process + suspicious keyword.
        condition = "selection_image and selection_keywords"
    elif selections:
        condition = " and ".join(selections)
    else:
        condition = "1 of selection_*"
    lines += [f"  condition: {condition}", "falsepositives:", "  - Legitimate administrative activity", "level: medium"]
    return "\n".join(lines) + "\n"


def _reference_queries(technique_id: str, profile: Dict[str, Any]) -> Dict[str, str]:
    """Generate human-readable KQL/SPL references over a normalized schema.

    These are not vendor-universal queries. Real SIEM field names must be mapped.
    Sigma remains the portable source of truth in this project.
    """
    match = profile.get("match", {})
    terms = match.get("contains_any", [])
    images = match.get("image_endswith", [])
    parents = match.get("parent_image_endswith", [])
    targets = match.get("target_image_endswith", [])

    clauses_kql = []
    clauses_spl = []

    if images:
        image_clause = " or ".join(f"Image endswith {json.dumps(x)}" for x in images)
        clauses_kql.append(f"({image_clause})")
        spl_vals = " OR ".join(f'Image="*{x.replace(chr(92), "\\\\")}"' for x in images)
        clauses_spl.append(f"({spl_vals})")
    if parents:
        parent_clause = " or ".join(f"ParentImage endswith {json.dumps(x)}" for x in parents)
        clauses_kql.append(f"({parent_clause})")
        spl_vals = " OR ".join(f'ParentImage="*{x.replace(chr(92), "\\\\")}"' for x in parents)
        clauses_spl.append(f"({spl_vals})")
    if targets:
        target_clause = " or ".join(f"TargetImage endswith {json.dumps(x)}" for x in targets)
        clauses_kql.append(f"({target_clause})")
        spl_vals = " OR ".join(f'TargetImage="*{x.replace(chr(92), "\\\\")}"' for x in targets)
        clauses_spl.append(f"({spl_vals})")
    if terms:
        k = " or ".join(f'CommandLine contains {json.dumps(t)}' for t in terms)
        clauses_kql.append(f"({k})")
        s = " OR ".join(f'CommandLine="*{t}*"' for t in terms)
        clauses_spl.append(f"({s})")

    kql_filter = " and ".join(clauses_kql) if clauses_kql else "true"
    spl_filter = " ".join(clauses_spl) if clauses_spl else "*"
    return {
        "kql_reference": f"SecurityEvents | where {kql_filter} | extend TechniqueId=\"{technique_id}\"",
        "spl_reference": f"index=security {spl_filter} | eval TechniqueId=\"{technique_id}\"",
    }


def build_hunting_plan(cti_result: Dict[str, Any]) -> Dict[str, Any]:
    technique_id = str(cti_result.get("technique_id", "")).upper().strip()
    profile = get_profile(technique_id)
    if not profile:
        return {
            "technique_id": technique_id or "UNKNOWN",
            "supported": False,
            "hypothesis": "No deterministic hunting profile is available for this technique yet.",
            "telemetry": [],
            "evidence": cti_result.get("evidence", ""),
            "sigma_rule": None,
            "queries": {},
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

    return {
        "technique_id": technique_id,
        "technique_name": profile["name"],
        "tactic": profile["tactic"],
        "supported": True,
        "hypothesis": profile["hypothesis"],
        "telemetry": profile["telemetry"],
        "evidence": cti_result.get("evidence", ""),
        "sigma_rule": _sigma_yaml(technique_id, profile),
        "queries": _reference_queries(technique_id, profile),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
