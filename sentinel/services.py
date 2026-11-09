"""One small service per architecture stage. Each reads one bus topic and publishes the next (Single Responsibility)."""
from __future__ import annotations
from sentinel.baseline.rules import RuleBaseline
from sentinel.config import Settings
from sentinel.correlation.attack_map import AttackMapper
from sentinel.domain.interfaces import (AuditLog, Correlator, Detector, EventBus, EventSource, EventStore, Normalizer,
                                        Repository, TriageAgent)
from sentinel.domain.models import Alert, Event, Incident, TriageReport
from sentinel.response.orchestrator import ResponseOrchestrator


class SimClock:
    def __init__(self) -> None:
        self.now = 0.0

    def advance(self, ts: float) -> None:
        self.now = max(self.now, ts)


class IngestService:                       # raw.events -> events
    def __init__(self, normalizer: Normalizer, store: EventStore, bus: EventBus, clock: SimClock) -> None:
        self._n, self._store, self._bus, self._clock = normalizer, store, bus, clock

    def on_raw(self, raw: dict) -> None:
        event = self._n.normalize(raw)
        self._store.add(event); self._clock.advance(event.ts)
        self._bus.publish("events", event)


class DetectionService:                    # events -> alerts
    BAD_PREFIXES = ("missing:", "suspicious:")

    def __init__(self, detectors: list[Detector], alerts: Repository, bus: EventBus, audit: AuditLog) -> None:
        self._dets, self._alerts, self._bus, self._audit = detectors, alerts, bus, audit

    def on_event(self, event: Event) -> None:
        bad = [f for f in event.quality_flags if f.startswith(self.BAD_PREFIXES)]
        if bad:                             # missing or misleading data: abstain and say so
            self._audit.append("sentinel", "detector_abstained", {"event": event.id, "flags": bad}, ts=event.ts)
            return
        for det in self._dets:
            if det.supports(event) and (alert := det.detect(event)):
                self._alerts.save(alert)
                self._bus.publish("alerts", alert)


class CorrelationService:                  # alerts -> incidents
    def __init__(self, store: EventStore, mapper: AttackMapper, correlator: Correlator, bus: EventBus) -> None:
        self._store, self._mapper, self._corr, self._bus = store, mapper, correlator, bus

    def on_alert(self, alert: Alert) -> None:
        event = self._store.get(alert.event_id)
        self._bus.publish("incidents", self._corr.add(alert, self._mapper.map(alert, event), event))


class TriageService:                       # incidents -> reports -> actions
    def __init__(self, agent: TriageAgent, reports: dict[str, TriageReport], orchestrator: ResponseOrchestrator,
                 audit: AuditLog, settings: Settings) -> None:
        self._agent, self._reports, self._orch, self._audit, self._s = agent, reports, orchestrator, audit, settings
        self._seen: dict[str, tuple[set[str], int]] = {}

    def on_incident(self, inc: Incident) -> None:
        if inc.severity_score < self._s.triage_min_severity:
            return                          # uncertain single alerts wait for corroboration
        techniques, count = {t.id for t in inc.techniques}, len(inc.alert_ids)
        if inc.id in self._seen:
            old_t, old_n = self._seen[inc.id]
            if techniques <= old_t and count < 2 * old_n:
                return                      # nothing new: re-triage only on a new technique or when evidence doubles
        self._seen[inc.id] = (techniques, count)
        report = self._agent.triage(inc)
        self._reports[inc.id] = report
        self._audit.append("sentinel", "triage_report", {"incident": inc.id, "severity": report.severity,
                           "confidence": report.confidence, "by": report.produced_by, "summary": report.summary}, ts=inc.last_ts)
        self._orch.plan(report, now=inc.last_ts)


class BaselineService:
    def __init__(self, baseline: RuleBaseline) -> None:
        self._b = baseline

    def on_event(self, event: Event) -> None:
        self._b.process(event)


class SentinelPipeline:
    def __init__(self, bus: EventBus) -> None:
        self._bus = bus

    def run(self, source: EventSource) -> int:
        n = 0
        for raw in source.stream():
            self._bus.publish("raw.events", raw); n += 1
        return n
