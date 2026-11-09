"""Entity-graph correlation: alerts that share a user, host or IP within a time window become one incident."""
from __future__ import annotations
from datetime import datetime, timezone
import networkx as nx
from sentinel.domain.interfaces import Correlator
from sentinel.domain.models import Alert, Event, Incident, TechniqueHit


def severity_label(score: float) -> str:
    return "critical" if score >= 0.9 else "high" if score >= 0.75 else "medium" if score >= 0.5 else "low"


def entities_of(a: Alert) -> set[str]:
    ents = {f"user:{a.user}" if a.user else None, f"host:{a.host}" if a.host else None,
            f"ip:{a.src_ip}" if a.src_ip else None}
    if a.dst_ip and not a.dst_ip.startswith("10."):
        ents.add(f"ip:{a.dst_ip}")                    # external destinations link C2 / exfil flows
    return ents - {None}


class EntityGraphCorrelator(Correlator):
    def __init__(self, window_s: float) -> None:
        self.window, self.graph, self._incidents = window_s, nx.Graph(), []
        self._alert_conf: dict[str, list[float]] = {}

    def add(self, alert: Alert, hits: list[TechniqueHit], event: Event) -> Incident:
        ents = entities_of(alert)
        self.graph.add_nodes_from(ents)
        first = next(iter(ents))
        for other in ents:
            self.graph.add_edge(first, other)
        component = nx.node_connected_component(self.graph, first)
        related = [i for i in self._incidents if set(i.entities) & component and alert.ts - i.last_ts <= self.window]
        if related:
            inc, rest = related[0], related[1:]
            for other in rest:                           # merge incidents the new alert has just bridged
                self._merge(inc, other)
                self._incidents.remove(other)
        else:
            inc = Incident(first_ts=alert.ts, last_ts=alert.ts)
            self._alert_conf[inc.id] = []
            self._incidents.append(inc)
        self._update(inc, alert, hits, ents, event)
        return inc

    def incidents(self) -> list[Incident]:
        return list(self._incidents)

    def _merge(self, inc: Incident, other: Incident) -> None:
        inc.entities = sorted(set(inc.entities) | set(other.entities))
        inc.alert_ids += other.alert_ids; inc.event_ids += other.event_ids
        inc.techniques += other.techniques; inc.timeline = sorted(inc.timeline + other.timeline)
        inc.first_ts = min(inc.first_ts, other.first_ts)
        self._alert_conf[inc.id] += self._alert_conf.pop(other.id, [])

    def _update(self, inc, alert, hits, ents, event) -> None:
        inc.entities = sorted(set(inc.entities) | ents)
        inc.alert_ids.append(alert.id); inc.event_ids.append(event.id)
        inc.techniques += hits
        inc.last_ts = max(inc.last_ts, alert.ts)
        stamp = datetime.fromtimestamp(alert.ts, timezone.utc).strftime("%H:%M:%S")
        inc.timeline.append(f"{stamp} {alert.detector}: {alert.reason}")
        conf = self._alert_conf[inc.id]; conf.append(alert.confidence)
        remaining = 1.0
        for c in conf:
            remaining *= (1 - c)                         # noisy-or: independent alerts reinforce each other
        inc.severity_score = round(1 - remaining, 4)
        inc.severity = severity_label(inc.severity_score)
