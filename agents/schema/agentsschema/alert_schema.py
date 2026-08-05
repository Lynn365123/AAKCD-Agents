"""
Shared AAKCD alert schema.

Every one of the 6 agents (Recon, Delivery, Exploitation, Installation, C2,
Coordinator) must emit alerts in exactly this shape. This is the single
source of truth the whole team imports -- do not build a local copy of
this file per agent, or the schema will drift (this was the reference
team's biggest integration headache).

Usage:
    from schema.alert_schema import Alert, MitreMapping, write_alert

    alert = Alert(
        agent_id="010",
        agent_ip="100.100.246.113",
        agent_name="Recon_Agent",
        target_host="192.168.88.129",
        category="network_recon",
        confidence="high",
        description="Open TCP port 21 (ftp) with anonymous login enabled.",
        mitre=MitreMapping(technique="T1046", tactic="Discovery"),
        severity=12,
        recommended_action="Restrict port 21 to trusted hosts or disable the service.",
    )
    write_alert(alert, "recon_alerts.jsonl")
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

Confidence = Literal["low", "medium", "high"]


@dataclass
class MitreMapping:
    technique: str  # e.g. "T1046"
    tactic: str      # e.g. "Discovery"


@dataclass
class Alert:
    agent_id: str
    agent_ip: str
    agent_name: str          # e.g. "Recon_Agent", "Delivery_Agent", "Coordinator_Agent"
    target_host: str         # correlation key -- the IP/hostname this alert is about
    category: str            # e.g. "network_recon", "email_phishing", "bash_execution"
    confidence: Confidence
    description: str         # human-readable summary an analyst can read directly
    mitre: MitreMapping
    severity: int             # 0-12, matching the reference team's Wazuh severity scale
    recommended_action: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def validate(self) -> None:
        """Raise ValueError if this alert doesn't conform to the shared schema."""
        if self.confidence not in ("low", "medium", "high"):
            raise ValueError(f"confidence must be low/medium/high, got {self.confidence!r}")
        if not (0 <= self.severity <= 12):
            raise ValueError(f"severity must be 0-12, got {self.severity!r}")
        if not self.mitre.technique.startswith("T"):
            raise ValueError(f"mitre.technique should look like 'T1046', got {self.mitre.technique!r}")
        if not self.target_host:
            raise ValueError("target_host is required -- it's the correlation key the Coordinator uses")

    def to_dict(self) -> dict:
        return {
            "@timestamp": self.timestamp,
            "agent": {
                "id": self.agent_id,
                "ip": self.agent_ip,
                "name": self.agent_name,
            },
            "data": {
                "target_host": self.target_host,
                "category": self.category,
                "confidence": self.confidence,
                "description": self.description,
                "mitre": {
                    "technique": self.mitre.technique,
                    "tactic": self.mitre.tactic,
                },
                "severity": self.severity,
                "recommended_action": self.recommended_action,
            },
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False)


def write_alert(alert: Alert, log_path: str | Path) -> None:
    """Validate and append one alert as a JSON line to a local log file.

    In Week 6-7 this is all agents do (write to a local file). Once the
    Wazuh decoder/rule for this schema is in place, the same log file is
    tailed by the Wazuh agent on that VM -- no code change needed here.
    """
    alert.validate()
    path = Path(log_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(alert.to_json() + "\n")


def read_alerts(log_path: str | Path) -> list[dict]:
    """Read back all alerts from a local JSONL log -- useful for the
    Coordinator agent's local testing before it has real Wazuh access."""
    path = Path(log_path)
    if not path.exists():
        return []
    with path.open(encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]
