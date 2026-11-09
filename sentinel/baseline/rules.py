"""The comparison baseline: stateless, Sigma-style rules that send every match straight to an analyst."""
from __future__ import annotations
from dataclasses import dataclass
from typing import Callable
from sentinel.detection.features import hour_of
from sentinel.domain.models import BaselineAlert, Event, EventKind


@dataclass
class Rule:
    id: str
    title: str
    applies: Callable[[Event], bool]


def default_rules() -> list[Rule]:
    A = lambda e: e.attrs
    return [
        Rule("B1", "5+ failed logins", lambda e: e.kind == EventKind.AUTH and A(e).get("failed_1h", 0) >= 5),
        Rule("B2", "PowerShell with -enc or bypass", lambda e: e.kind == EventKind.ENDPOINT and A(e)["process"].lower() == "powershell.exe"
             and (" -enc " in A(e).get("cmdline", "").lower() or "bypass" in A(e).get("cmdline", "").lower())),
        Rule("B3", "Login between 00:00 and 05:59", lambda e: e.kind == EventKind.AUTH and hour_of(e.ts) < 6),
        Rule("B4", "Transfer over 50 MB", lambda e: e.kind == EventKind.FLOW and A(e)["fwd_bytes"] > 50_000_000),
        Rule("B5", "PsExec execution", lambda e: e.kind == EventKind.ENDPOINT and A(e)["process"].lower() in {"psexec.exe", "psexesvc.exe"}),
        Rule("B6", "SMB probe (no reply)", lambda e: e.kind == EventKind.FLOW and A(e)["dst_port"] == 445 and A(e)["bwd_pkts"] == 0),
        Rule("B7", "Login from >1000 km away", lambda e: e.kind == EventKind.AUTH and A(e).get("geo_km", 0) > 1000),
    ]


class RuleBaseline:
    def __init__(self, rules: list[Rule] | None = None) -> None:
        self.rules = rules if rules is not None else default_rules()
        self.alerts: list[BaselineAlert] = []

    def process(self, e: Event) -> list[BaselineAlert]:
        hits = [BaselineAlert(rule_id=r.id, title=r.title, event_id=e.id, ts=e.ts) for r in self.rules if r.applies(e)]
        self.alerts += hits
        return hits
