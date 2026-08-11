"""The deterministic history seed. Spec: enrichment-05-spec.md §14.

Every seeded alert's occurred_at is CORPUS_EPOCH - offset, never now() - offset.
Seeding relative to run time is wrong here and silently so: the fixture corpus has
fixed occurred_at values in 2026-07-19/20, so a history seeded at today's date sits
in the *future* relative to every fixture, the window filter excludes all of it, and
every fixture correlates to nothing — which looks exactly like a working pipeline on
an alert with no history.

Each group exists to produce one fixture's labeled history component (§16.1). The
counts are not decorative.
"""

from __future__ import annotations

import random
import sqlite3
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from soc_agent.extract.merge import canonical_value
from soc_agent.providers.history.sqlite import SCHEMA_SQL, SCHEMA_VERSION, to_utc_text

CORPUS_EPOCH = datetime(2026, 7, 20, 12, 0, 0, tzinfo=UTC)
SEED_VERSION = "1"

# Fixture 10 is the only alert with occurred_at: null, so its window anchors on
# ingested_at (wall clock) and would slide forward daily. It is given zero relations
# instead of a special-cased anchor, which makes its output time-invariant by
# construction (§4.3). These values are RESERVED — seeding any of them re-introduces
# the drift, and test_history_seed.py asserts their absence.
RESERVED_FIXTURE_10_VALUES = frozenset({"ws-hr-0009", "t.baros", "203.0.113.150", "powershell"})


@dataclass(frozen=True)
class SeedAlert:
    alert_id: str
    offset: timedelta  # before the epoch
    title: str
    severity: int
    disposition: str
    vendor_rule: str | None = None
    category: str | None = None
    entities: tuple[tuple[str, str], ...] = ()


@dataclass
class SeedSummary:
    alerts: int = 0
    epoch: str = ""
    rules: dict[str, int] = field(default_factory=dict)
    dispositions: dict[str, int] = field(default_factory=dict)


def _at(days: float, hours: float = 0, minutes: float = 0) -> timedelta:
    return timedelta(days=days, hours=hours, minutes=minutes)


RULE_FAILED_LOGINS = "Access - Excessive Failed Logins - Rule"
RULE_HASH_BLOCKLIST = "Hash matched local blocklist"
RULE_PORT_SCAN = "Network - Port Scan Detected - Rule"


# --- Group A: WS-FIN-0142 / l.hassan cluster -> fixtures 01 and 05 -------------
#
# The subtle one. Fixtures 01 and 05 share WS-FIN-0142, l.hassan and 10.20.14.88, so
# any alert touching those relates to both. But 01 needs exactly 2 relations (-> 75,
# reproducing Architecture Appendix B's worked example) while 05 needs 3 (-> 85, the
# only value that puts it over the investigate line, §16.2). A3 therefore carries only
# fixture 05's *unshared* entities.
_GROUP_A = (
    SeedAlert(
        # Appendix B verbatim: same id, timestamp, title, severity and disposition.
        alert_id="SIEM-2026-017901",
        offset=_at(5, 8, 38),  # 2026-07-15T03:22:00Z
        title="EDR: suspicious rundll32 network activity",
        severity=80,
        disposition="true_positive",
        vendor_rule="EDR - Suspicious Process Network Activity",
        category="malware",
        entities=(("host", "WS-FIN-0142"),),
    ),
    SeedAlert(
        alert_id="SIEM-2026-017988",
        offset=_at(3, 2, 46),  # 2026-07-17T09:14:00Z
        title="Blocked download from uncategorized site",
        severity=40,
        disposition="benign",
        vendor_rule="Proxy - Uncategorized Destination",
        category="policy_violation",
        entities=(("user", "l.hassan"), ("ip", "10.20.14.88")),
    ),
    SeedAlert(
        alert_id="SIEM-2026-018050",
        offset=_at(1, 21, 55),  # 2026-07-18T14:05:00Z
        title="SMB share enumeration on FS-CORP-03",
        severity=55,
        disposition="undetermined",
        vendor_rule="NDR - SMB Enumeration",
        category="lateral_movement",
        entities=(("host", "FS-CORP-03"), ("ip", "10.20.30.12")),
    ),
)

# --- Group B: j.okafor phishing history -> fixture 02 -------------------------
_GROUP_B = (
    SeedAlert(
        alert_id="SIEM-2026-017455",
        offset=_at(22, 1, 49),  # 2026-06-28T10:11:00Z
        title="Phishing email with credential-harvesting link",
        severity=80,
        disposition="true_positive",
        vendor_rule="Email - Reported Phishing",
        category="phishing",
        entities=(("user", "j.okafor"), ("domain", "login-verify.example-mail.test")),
    ),
    SeedAlert(
        alert_id="SIEM-2026-017602",
        offset=_at(15, 3, 13),  # 2026-07-05T08:47:00Z
        title="User reported phishing - malicious attachment",
        severity=75,
        disposition="true_positive",
        vendor_rule="Email - Reported Phishing",
        category="phishing",
        entities=(("user", "j.okafor"),),
    ),
    SeedAlert(
        alert_id="SIEM-2026-017815",
        offset=_at(7, 22, 30),  # 2026-07-12T13:30:00Z
        title="Credential submission to known phishing page",
        severity=85,
        disposition="true_positive",
        vendor_rule="Email - Reported Phishing",
        category="phishing",
        entities=(("user", "j.okafor"),),
    ),
    SeedAlert(
        alert_id="SIEM-2026-017840",
        offset=_at(6, 19, 58),  # 2026-07-13T16:02:00Z
        title="Marketing bulk mail flagged by content filter",
        severity=20,
        disposition="false_positive",
        vendor_rule="Email - Content Filter",
        category="policy_violation",
        entities=(("user", "j.okafor"),),
    ),
)

# --- Group C: BASTION-01 / admin -> fixture 03 --------------------------------
_GROUP_C = (
    SeedAlert(
        alert_id="SIEM-2026-017733",
        offset=_at(11, 9, 19),  # 2026-07-09T02:41:00Z
        title="Successful login after failed-login burst",
        severity=70,
        disposition="true_positive",
        vendor_rule="Access - Anomalous Successful Login",
        category="credential_access",
        entities=(("host", "BASTION-01"), ("user", "admin"), ("ip", "198.51.100.90")),
    ),
    SeedAlert(
        alert_id="SIEM-2026-017799",
        offset=_at(8, 13, 42),  # 2026-07-11T22:18:00Z
        title=RULE_FAILED_LOGINS,
        severity=45,
        disposition="false_positive",
        vendor_rule=RULE_FAILED_LOGINS,
        category="credential_access",
        entities=(("host", "BASTION-01"), ("user", "admin")),
    ),
    SeedAlert(
        alert_id="SIEM-2026-017902",
        offset=_at(5, 7, 5),  # 2026-07-15T04:55:00Z
        title="Successful SSH login after failed-login burst",
        severity=65,
        disposition="true_positive",
        vendor_rule=RULE_FAILED_LOGINS,
        category="credential_access",
        entities=(("host", "BASTION-01"), ("user", "svc_deploy")),
    ),
    SeedAlert(
        alert_id="SIEM-2026-018012",
        offset=_at(2, 16, 57),  # 2026-07-17T19:03:00Z
        title=RULE_FAILED_LOGINS,
        severity=50,
        disposition="undetermined",
        vendor_rule=RULE_FAILED_LOGINS,
        category="credential_access",
        entities=(("user", "admin"), ("ip", "10.20.7.5")),
    ),
)

# --- Group E: sso-gateway / m.silva -> fixture 06 (neutral: <= 2, no TP) -------
_GROUP_E = (
    SeedAlert(
        alert_id="SIEM-2026-017710",
        offset=_at(12, 0, 40),  # 2026-07-08T11:20:00Z
        title="MFA challenge from new device",
        severity=35,
        disposition="benign",
        vendor_rule="Identity - New Device MFA",
        category="initial_access",
        entities=(("user", "m.silva"), ("host", "sso-gateway")),
    ),
    SeedAlert(
        alert_id="SIEM-2026-017950",
        offset=_at(4, 5, 16),  # 2026-07-16T06:44:00Z
        title="Sign-in from unfamiliar ASN",
        severity=45,
        disposition="undetermined",
        vendor_rule="Identity - Unfamiliar ASN",
        category="initial_access",
        entities=(("host", "sso-gateway"),),
    ),
)

# --- Group G: SRV-DB-02 -> fixture 09 (neutral) -------------------------------
_GROUP_G = (
    SeedAlert(
        alert_id="SIEM-2026-017520",
        offset=_at(17, 12, 10),  # 2026-07-02T23:50:00Z
        title="Scheduled backup transfer volume spike",
        severity=30,
        disposition="benign",
        vendor_rule="DLP - Volume Baseline Deviation",
        category="exfiltration",
        entities=(("host", "SRV-DB-02"), ("user", "svc_backup")),
    ),
)

# --- Group J: WS-MKT-0077 -> fixture 07 (neutral) -----------------------------
_GROUP_J = (
    SeedAlert(
        alert_id="SIEM-2026-017870",
        offset=_at(6, 1, 25),  # 2026-07-14T10:35:00Z
        title="DNS query to low-reputation domain",
        severity=40,
        disposition="undetermined",
        vendor_rule="DNS - Low Reputation Destination",
        category="command_and_control",
        entities=(
            ("host", "WS-MKT-0077"),
            ("user", "s.novak"),
            ("domain", "ads-tracker.example-cdn.test"),
        ),
    ),
)


def _group_d() -> tuple[SeedAlert, ...]:
    """Rule 'Hash matched local blocklist': 11 FP + 1 TP -> fp_rate 0.917, fired 12.

    Exactly one alert (an FP) shares WS-ENG-0231 with fixture 04. The single TP shares
    nothing with it: if it did, fixture 04 would gain the +25 "related TP shares an
    entity" bonus and drift toward the wrong band (§14.2).
    """
    hosts = [
        "WS-ENG-0231",  # the one that shares with fixture 04
        "WS-ENG-0110",
        "WS-SAL-0043",
        "WS-ENG-0277",
        "WS-FIN-0301",
        "WS-OPS-0018",
        "WS-ENG-0155",
        "WS-SAL-0090",
        "WS-HR-0044",
        "WS-OPS-0062",
        "WS-ENG-0203",
        "WS-LAB-0007",  # the TP
    ]
    alerts = []
    for index, host in enumerate(hosts):
        is_tp = index == len(hosts) - 1
        alerts.append(
            SeedAlert(
                alert_id=f"SIEM-2026-016{400 + index:03d}",
                offset=_at(25 - index * 2, 3, index * 7 % 60),
                title=RULE_HASH_BLOCKLIST,
                severity=60 if is_tp else 45,
                disposition="true_positive" if is_tp else "false_positive",
                vendor_rule=RULE_HASH_BLOCKLIST,
                category="malware",
                entities=(("host", host),),
            )
        )
    return tuple(alerts)


def _group_f() -> tuple[SeedAlert, ...]:
    """Rule 'Network - Port Scan Detected - Rule': 38 FP + 2 TP -> fp_rate 0.95, fired 40.

    Five FPs share 10.20.0.15 with fixture 08; the two TPs share nothing with it, so
    fixture 08 gets +10 (>= 3 shared-entity relations) and -25 (noisy rule) but never
    the +25 prior-TP bonus.

    40 rows rather than a fudged aggregate: rule_stats computes from rows, so a summary
    table would leave the one fixture that exercises it untested. It also gives the
    §12.4 truncation case something real to truncate.
    """
    rng = random.Random(20260720)
    alerts = []
    for index in range(40):
        is_tp = index in (17, 33)
        shares_dest = index < 5 and not is_tp
        source = f"198.51.100.{201 if shares_dest else 100 + index}"
        entities: tuple[tuple[str, str], ...] = (("ip", source),)
        if shares_dest:
            entities += (("ip", "10.20.0.15"),)
        else:
            entities += (("ip", f"10.20.{rng.randint(1, 60)}.{rng.randint(2, 250)}"),)
        alerts.append(
            SeedAlert(
                alert_id=f"SIEM-2026-018{100 + index:03d}",
                offset=_at(28 - index * 0.6, 1, index * 13 % 60),
                title=RULE_PORT_SCAN,
                severity=40 if is_tp else 25,
                disposition="true_positive" if is_tp else "false_positive",
                vendor_rule=RULE_PORT_SCAN,
                category="reconnaissance",
                entities=entities,
            )
        )
    return tuple(alerts)


def _group_i() -> tuple[SeedAlert, ...]:
    """Filler: unrelated alerts so the store looks real and find_related has negatives
    to reject. Shares no entity with any fixture."""
    rows = [
        (
            "SIEM-2026-017300",
            29,
            "Outbound connection to Tor exit node",
            55,
            "true_positive",
            "NDR - Anonymizer Destination",
            "command_and_control",
            (("ip", "203.0.113.44"), ("host", "WS-LAB-0021")),
        ),
        (
            "SIEM-2026-017340",
            27,
            "Suspicious archive extracted in temp path",
            50,
            "false_positive",
            "EDR - Archive In Temp",
            "malware",
            (("host", "WS-SAL-0112"), ("user", "r.patel")),
        ),
        (
            "SIEM-2026-017390",
            24,
            "Service account login outside business hours",
            45,
            "benign",
            "Access - Off-Hours Service Login",
            "credential_access",
            (("user", "svc_report"), ("host", "APP-RPT-01")),
        ),
        (
            "SIEM-2026-017430",
            21,
            "Fake software update download",
            70,
            "true_positive",
            "Proxy - Malware Distribution",
            "malware",
            (("domain", "updates.example-softsync.test"), ("host", "WS-ENG-0402")),
        ),
        (
            "SIEM-2026-017560",
            16,
            "USB mass storage attached",
            25,
            "benign",
            "Endpoint - Removable Media",
            "policy_violation",
            (("host", "WS-FIN-0501"), ("user", "k.ibrahim")),
        ),
        (
            "SIEM-2026-017650",
            13,
            "Excessive DNS TXT queries",
            60,
            "undetermined",
            "DNS - TXT Volume Anomaly",
            "command_and_control",
            (("host", "WS-OPS-0330"), ("ip", "10.20.44.19")),
        ),
        (
            "SIEM-2026-017690",
            10,
            "Kerberoasting-style ticket requests",
            75,
            "open",
            "Identity - Anomalous Ticket Requests",
            "credential_access",
            (("user", "a.moreau"), ("host", "DC-CORP-01")),
        ),
        (
            "SIEM-2026-017960",
            4,
            "Cloud storage upload above baseline",
            40,
            "false_positive",
            "DLP - Cloud Upload Baseline",
            "exfiltration",
            (("host", "WS-MKT-0512"), ("user", "p.andersen")),
        ),
    ]
    return tuple(
        SeedAlert(
            alert_id=alert_id,
            offset=_at(days, 6, 30),
            title=title,
            severity=severity,
            disposition=disposition,
            vendor_rule=rule,
            category=category,
            entities=entities,
        )
        for alert_id, days, title, severity, disposition, rule, category, entities in rows
    )


def corpus() -> tuple[SeedAlert, ...]:
    """All groups in a fixed order. Group H (fixture 10) is deliberately empty (§4.3)."""
    return (
        *_GROUP_A,
        *_GROUP_B,
        *_GROUP_C,
        *_group_d(),
        *_GROUP_E,
        *_group_f(),
        *_GROUP_G,
        *_GROUP_J,
        *_group_i(),
    )


def seed_history(conn: sqlite3.Connection, *, epoch: datetime = CORPUS_EPOCH) -> SeedSummary:
    """Create the schema and insert the corpus. Deterministic: same epoch -> same rows."""
    conn.executescript(SCHEMA_SQL)
    alerts = corpus()

    summary = SeedSummary(alerts=len(alerts), epoch=to_utc_text(epoch))
    for alert in alerts:
        occurred_at = to_utc_text(epoch - alert.offset)
        conn.execute(
            "INSERT INTO alerts (alert_id, occurred_at, title, severity, vendor_rule, "
            "category, disposition) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                alert.alert_id,
                occurred_at,
                alert.title,
                alert.severity,
                alert.vendor_rule,
                alert.category,
                alert.disposition,
            ),
        )
        for entity_type, value in alert.entities:
            # Stored already canonicalized so the query side never needs LOWER() and
            # idx_entities_value is actually usable (§11.1).
            conn.execute(
                "INSERT OR IGNORE INTO alert_entities (alert_id, type, value) VALUES (?, ?, ?)",
                (alert.alert_id, entity_type, canonical_value(entity_type, value)),
            )
        if alert.vendor_rule:
            summary.rules[alert.vendor_rule] = summary.rules.get(alert.vendor_rule, 0) + 1
        summary.dispositions[alert.disposition] = summary.dispositions.get(alert.disposition, 0) + 1

    for key, value in (
        ("schema_version", SCHEMA_VERSION),
        ("epoch", summary.epoch),
        ("seed_version", SEED_VERSION),
        ("generated_alerts", str(len(alerts))),
    ):
        conn.execute("INSERT INTO meta (key, value) VALUES (?, ?)", (key, value))
    conn.commit()
    return summary


def build_seeded_db(path: str, *, epoch: datetime = CORPUS_EPOCH) -> SeedSummary:
    """Create a fresh DB file at `path`. The caller is responsible for removing any
    existing file — `soc-agent seed` requires --force for that."""
    conn = sqlite3.connect(path)
    try:
        return seed_history(conn, epoch=epoch)
    finally:
        conn.close()
