"""Keyword + ECS category inference. Spec: ingestion-03-spec.md §7.

Matching is word-boundary regex, not substring — a naive substring test for the
"c2" keyword matches inside hex digests like "sha256=4c2fa1e0b93f...", misclassifying
malware alerts as command_and_control. See §7 for the verified fixture walkthrough.
"""

from __future__ import annotations

import re

from soc_agent.models import AlertCategory

_TABLE: list[tuple[list[str], AlertCategory]] = [
    (
        ["impossible travel", "unusual sign-in location", "anomalous login location"],
        "initial_access",
    ),
    (
        [
            "lateral movement",
            "psexec",
            "smb share access",
            "remote service creation",
            "pass-the-hash",
        ],
        "lateral_movement",
    ),
    (["exfil", "data volume", "outbound data", "large upload", "dlp"], "exfiltration"),
    (["port scan", "portscan", "network scan", "host discovery", "enumeration"], "reconnaissance"),
    (
        [
            "brute force",
            "failed login",
            "failed logins",
            "failed password",
            "password spray",
            "credential dump",
        ],
        "credential_access",
    ),
    (["phish", "malicious email", "suspicious attachment", "invoice overdue"], "phishing"),
    (
        [
            "beacon",
            "command and control",
            "c2",
            "newly registered domain",
            "dns tunnel",
            "rare external host",
        ],
        "command_and_control",
    ),
    (
        [
            "malware",
            "blocklist",
            "hash match",
            "ransomware",
            "trojan",
            "powershell",
            "encoded command",
        ],
        "malware",
    ),
    (["persistence", "scheduled task", "run key", "autorun"], "persistence"),
    (["policy violation", "unauthorized software"], "policy_violation"),
    (["anomaly", "deviation from baseline"], "anomaly"),
]

_COMPILED: list[tuple[list[re.Pattern[str]], AlertCategory]] = [
    ([re.compile(r"\b" + re.escape(kw) + r"\b") for kw in kws], cat) for kws, cat in _TABLE
]

_ECS_MAP: dict[str, AlertCategory] = {
    "malware": "malware",
    "intrusion_detection": "command_and_control",
    "authentication": "credential_access",
    "iam": "credential_access",
    "network": "anomaly",
    "process": "malware",
    "file": "malware",
}


def infer_category(
    *texts: str | None, ecs_categories: list[str] | None = None
) -> AlertCategory | None:
    """Keyword table first (specific), then the ECS event.category map (generic).

    None if neither hits — a missing category is legal and must not fail normalization.
    """
    blob = " ".join(t for t in texts if t).lower()
    for patterns, category in _COMPILED:
        if any(p.search(blob) for p in patterns):
            return category
    for ecs in ecs_categories or []:
        if ecs in _ECS_MAP:
            return _ECS_MAP[ecs]
    return None
