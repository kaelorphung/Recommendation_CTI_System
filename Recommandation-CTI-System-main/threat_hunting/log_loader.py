"""Load and normalize Windows/Sysmon hunting logs.

Supported directly: JSON, JSONL/NDJSON, CSV.
Optional: EVTX if `python-evtx` is installed.
"""

import csv
import json
import os
import xml.etree.ElementTree as ET
from typing import Any, Dict, Iterable, List


ALIASES = {
    "event_id": ["event_id", "EventID", "EventId", "eventid", "EventCode"],
    "timestamp": ["timestamp", "UtcTime", "TimeCreated", "@timestamp", "TimeGenerated"],
    "host": ["host", "Computer", "ComputerName", "Hostname"],
    "source": ["source", "Channel", "Provider", "log_name"],
    "image": ["image", "Image", "process_path", "ProcessName", "NewProcessName"],
    "parent_image": ["parent_image", "ParentImage", "ParentProcessName"],
    "command_line": ["command_line", "CommandLine", "ScriptBlockText", "Message", "ProcessCommandLine"],
    "user": ["user", "User", "UserName", "SubjectUserName"],
    "target_image": ["target_image", "TargetImage"],
    "destination_ip": ["destination_ip", "DestinationIp", "DestinationIP", "dest_ip"],
    "query_name": ["query_name", "QueryName", "DnsQuery"],
    "task_name": ["task_name", "TaskName"],
    "label": ["label", "Label", "ground_truth", "is_malicious"],
    "attack_technique": ["attack_technique", "TechniqueId", "technique_id", "mitre_attack"],
}


def _first(d: Dict[str, Any], names: Iterable[str], default=None):
    for n in names:
        if n in d and d[n] not in (None, ""):
            return d[n]
    return default


def normalize_event(event: Dict[str, Any]) -> Dict[str, Any]:
    out = {k: _first(event, aliases) for k, aliases in ALIASES.items()}
    try:
        out["event_id"] = int(out["event_id"]) if out["event_id"] is not None else None
    except (ValueError, TypeError):
        pass

    label = out.get("label")
    if isinstance(label, str):
        out["label"] = label.strip().lower() in {"1", "true", "malicious", "attack", "yes"}
    elif isinstance(label, (int, bool)):
        out["label"] = bool(label)

    out["raw"] = event
    return out


def _load_json(path: str) -> List[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8-sig") as f:
        obj = json.load(f)
    if isinstance(obj, list):
        return [normalize_event(x) for x in obj]
    if isinstance(obj, dict):
        if isinstance(obj.get("events"), list):
            return [normalize_event(x) for x in obj["events"]]
        return [normalize_event(obj)]
    raise ValueError("JSON log must contain an object, an array, or {'events': [...]}.")


def _load_jsonl(path: str) -> List[Dict[str, Any]]:
    events = []
    with open(path, "r", encoding="utf-8-sig") as f:
        for line in f:
            line = line.strip()
            if line:
                events.append(normalize_event(json.loads(line)))
    return events


def _load_csv(path: str) -> List[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8-sig", newline="") as f:
        return [normalize_event(row) for row in csv.DictReader(f)]


def _load_evtx(path: str) -> List[Dict[str, Any]]:
    try:
        from Evtx.Evtx import Evtx
    except ImportError as e:
        raise ImportError("EVTX support requires: pip install python-evtx") from e

    ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
    events = []
    with Evtx(path) as log:
        for record in log.records():
            root = ET.fromstring(record.xml())
            system = root.find("e:System", ns)
            event_data = root.find("e:EventData", ns)
            raw = {}
            if system is not None:
                eid = system.find("e:EventID", ns)
                computer = system.find("e:Computer", ns)
                channel = system.find("e:Channel", ns)
                time_created = system.find("e:TimeCreated", ns)
                raw["EventID"] = eid.text if eid is not None else None
                raw["Computer"] = computer.text if computer is not None else None
                raw["Channel"] = channel.text if channel is not None else None
                raw["UtcTime"] = time_created.attrib.get("SystemTime") if time_created is not None else None
            if event_data is not None:
                for item in event_data.findall("e:Data", ns):
                    name = item.attrib.get("Name")
                    if name:
                        raw[name] = item.text or ""
            events.append(normalize_event(raw))
    return events


def load_events(path: str) -> List[Dict[str, Any]]:
    if not os.path.exists(path):
        raise FileNotFoundError(path)
    ext = os.path.splitext(path)[1].lower()
    if ext == ".json":
        return _load_json(path)
    if ext in {".jsonl", ".ndjson"}:
        return _load_jsonl(path)
    if ext == ".csv":
        return _load_csv(path)
    if ext == ".evtx":
        return _load_evtx(path)
    raise ValueError(f"Unsupported log format: {ext}. Use JSON/JSONL/CSV or EVTX.")
