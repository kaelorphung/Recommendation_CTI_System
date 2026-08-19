"""Small ATT&CK-oriented hunting knowledge base used by the Phase 3 baseline.

The goal is reproducibility: an ATT&CK technique from Phase 2 is converted into
(1) a hunting hypothesis, (2) recommended telemetry, and (3) portable Sigma-like
logic.  An LLM can be added later, but the deterministic baseline is always kept
as a fallback and for benchmarking.
"""

TECHNIQUE_PROFILES = {
    "T1059.001": {
        "name": "Command and Scripting Interpreter: PowerShell",
        "tactic": ["Execution"],
        "hypothesis": (
            "An adversary may be abusing PowerShell to execute encoded or "
            "download-and-execute commands on Windows endpoints."
        ),
        "telemetry": [
            "Sysmon Event ID 1 - Process Create",
            "PowerShell Operational / Script Block Logging (Event ID 4104)",
            "Windows process creation auditing (if enabled)",
        ],
        "logsource": {"category": "process_creation", "product": "windows"},
        "match": {
            "event_ids": [1, 4104],
            "image_endswith": ["\\powershell.exe", "\\pwsh.exe"],
            "contains_any": [
                " -enc ", " -encodedcommand ", "invoke-expression", " iex(",
                "downloadstring", "downloadfile", "frombase64string",
                "invoke-webrequest", " iwr ", "new-object net.webclient",
            ],
        },
        "sigma": {
            "title": "Suspicious PowerShell Execution",
            "selection_image": ["\\powershell.exe", "\\pwsh.exe"],
            "selection_keywords": [
                "-enc", "-encodedcommand", "Invoke-Expression", "IEX(",
                "DownloadString", "DownloadFile", "FromBase64String",
                "Invoke-WebRequest", "New-Object Net.WebClient",
            ],
        },
    },
    "T1053.005": {
        "name": "Scheduled Task/Job: Scheduled Task",
        "tactic": ["Execution", "Persistence", "Privilege Escalation"],
        "hypothesis": (
            "An adversary may create or modify a Windows Scheduled Task to "
            "execute code repeatedly, at logon/startup, or under a privileged account."
        ),
        "telemetry": [
            "Windows Security Event ID 4698 - Scheduled Task created",
            "Task Scheduler Operational Event ID 106 - Task registered",
            "Sysmon Event ID 1 - schtasks.exe / PowerShell task creation",
        ],
        "logsource": {"product": "windows", "service": "security"},
        "match": {
            "event_ids": [4698, 106, 1],
            "image_endswith": ["\\schtasks.exe", "\\powershell.exe", "\\pwsh.exe"],
            "contains_any": [
                "schtasks /create", "register-scheduledtask", "new-scheduledtask",
                "scheduledtask", "task scheduler",
            ],
        },
        "sigma": {
            "title": "Suspicious Windows Scheduled Task Creation",
            "selection_image": ["\\schtasks.exe", "\\powershell.exe", "\\pwsh.exe"],
            "selection_keywords": [
                "schtasks /create", "Register-ScheduledTask", "New-ScheduledTask",
            ],
        },
    },
    "T1003.001": {
        "name": "OS Credential Dumping: LSASS Memory",
        "tactic": ["Credential Access"],
        "hypothesis": (
            "An adversary may attempt to access or dump LSASS process memory "
            "to recover credential material."
        ),
        "telemetry": [
            "Sysmon Event ID 10 - Process Access",
            "Sysmon Event ID 1 - Process Create",
            "EDR process-access / memory-dump telemetry",
        ],
        "logsource": {"product": "windows"},
        "match": {
            "event_ids": [10, 1],
            "target_image_endswith": ["\\lsass.exe"],
            "contains_any": [
                "lsass", "comsvcs.dll", "minidump", "procdump", "sekurlsa",
                "mimikatz",
            ],
        },
        "sigma": {
            "title": "Possible LSASS Credential Dumping",
            "selection_image": ["\\procdump.exe", "\\rundll32.exe", "\\mimikatz.exe"],
            "selection_keywords": ["lsass", "comsvcs.dll", "MiniDump", "sekurlsa"],
        },
    },
    "T1566.001": {
        "name": "Phishing: Spearphishing Attachment",
        "tactic": ["Initial Access"],
        "hypothesis": (
            "A malicious attachment may lead an Office or mail client process to "
            "spawn a script interpreter or LOLBin on a Windows endpoint."
        ),
        "telemetry": [
            "Sysmon Event ID 1 - Process Create",
            "Windows process creation telemetry",
            "Email gateway / attachment telemetry (if available)",
        ],
        "logsource": {"category": "process_creation", "product": "windows"},
        "match": {
            "event_ids": [1],
            "parent_image_endswith": [
                "\\winword.exe", "\\excel.exe", "\\powerpnt.exe", "\\outlook.exe"
            ],
            "image_endswith": [
                "\\powershell.exe", "\\cmd.exe", "\\wscript.exe", "\\cscript.exe",
                "\\mshta.exe", "\\rundll32.exe"
            ],
        },
        "sigma": {
            "title": "Office Process Spawning Suspicious Child Process",
            "selection_image": [
                "\\powershell.exe", "\\cmd.exe", "\\wscript.exe", "\\cscript.exe",
                "\\mshta.exe", "\\rundll32.exe"
            ],
            "selection_parent": [
                "\\winword.exe", "\\excel.exe", "\\powerpnt.exe", "\\outlook.exe"
            ],
        },
    },
}


def get_profile(technique_id: str):
    return TECHNIQUE_PROFILES.get(str(technique_id).strip().upper())
