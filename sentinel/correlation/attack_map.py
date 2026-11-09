"""MITRE ATT&CK mapping. Add a new technique by writing one more rule and registering it (Open/Closed)."""
from __future__ import annotations
from typing import Callable
from sentinel.detection.features import OFFICE, REMOTE_EXEC, is_internal
from sentinel.domain.interfaces import TechniqueRule
from sentinel.domain.models import Alert, Event, EventKind, TechniqueHit

Predicate = Callable[[Alert, Event], bool]


class PredicateRule(TechniqueRule):
    def __init__(self, tid: str, name: str, tactic: str, predicate: Predicate) -> None:
        self.t, self.pred = (tid, name, tactic), predicate

    def match(self, alert, event):
        return [self.t] if self.pred(alert, event) else []


def default_rules() -> list[TechniqueRule]:
    a = lambda e: e.attrs
    return [
        PredicateRule("T1566", "Phishing", "Initial Access",
                      lambda al, e: e.kind == EventKind.ENDPOINT and a(e).get("parent", "").lower() in OFFICE
                      and a(e)["process"].lower() in {"powershell.exe", "cmd.exe"}),
        PredicateRule("T1059.001", "PowerShell", "Execution",
                      lambda al, e: e.kind == EventKind.ENDPOINT and a(e)["process"].lower() == "powershell.exe"),
        PredicateRule("T1021.002", "SMB/Windows Admin Shares", "Lateral Movement",
                      lambda al, e: (e.kind == EventKind.ENDPOINT and a(e)["process"].lower() in REMOTE_EXEC)
                      or (e.kind == EventKind.FLOW and a(e)["dst_port"] == 445 and is_internal(e.dst_ip))),
        PredicateRule("T1569.002", "Service Execution", "Execution",
                      lambda al, e: e.kind == EventKind.ENDPOINT and a(e)["process"].lower() in REMOTE_EXEC),
        PredicateRule("T1110", "Brute Force", "Credential Access",
                      lambda al, e: e.kind == EventKind.AUTH and a(e).get("failed_1h", 0) >= 5),
        PredicateRule("T1078", "Valid Accounts", "Initial Access",
                      lambda al, e: e.kind == EventKind.AUTH and (a(e).get("new_device") or a(e).get("geo_km", 0) > 1000)),
        PredicateRule("T1071.001", "Web Protocols (C2)", "Command and Control",
                      lambda al, e: e.kind == EventKind.FLOW and not is_internal(e.dst_ip)
                      and a(e)["duration_ms"] > 30000 and a(e)["fwd_bytes"] < 1000),
        PredicateRule("T1041", "Exfiltration Over C2 Channel", "Exfiltration",
                      lambda al, e: e.kind == EventKind.FLOW and not is_internal(e.dst_ip) and a(e)["fwd_bytes"] > 50_000_000),
    ]


class AttackMapper:
    def __init__(self, rules: list[TechniqueRule] | None = None) -> None:
        self._rules = rules if rules is not None else default_rules()

    def register(self, rule: TechniqueRule) -> None:
        self._rules.append(rule)

    def map(self, alert: Alert, event: Event) -> list[TechniqueHit]:
        return [TechniqueHit(id=i, name=n, tactic=t, alert_id=alert.id)
                for rule in self._rules for i, n, t in rule.match(alert, event)]
