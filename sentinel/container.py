"""Composition root: the ONLY place that knows concrete classes. Everything else receives abstractions."""
from __future__ import annotations
import logging
from typing import Callable
from sentinel.baseline.rules import RuleBaseline
from sentinel.config import Settings
from sentinel.correlation.attack_map import AttackMapper
from sentinel.correlation.correlator import EntityGraphCorrelator
from sentinel.detection.detectors import AuthDetector, EndpointDetector, FlowDetector
from sentinel.detection.features import AuthFeatures, EndpointFeatures, FlowFeatures
from sentinel.evaluation.metrics import Evaluator
from sentinel.infra.audit import SqliteAuditLog
from sentinel.infra.bus import InMemoryBus
from sentinel.infra.repositories import InMemoryEventStore, InMemoryRepository
from sentinel.ingestion.normalizer import RawRecordNormalizer
from sentinel.response.executors import MockEdrExecutor, MockFirewallExecutor, MockIdentityExecutor, MockTicketExecutor
from sentinel.response.orchestrator import ResponseOrchestrator
from sentinel.response.policy import RiskPolicy
from sentinel.services import (BaselineService, CorrelationService, DetectionService, IngestService, SentinelPipeline,
                               SimClock, TriageService)
from sentinel.sources.synthetic import SyntheticAttackRange
from sentinel.triage.agents import LLMTriageAgent, RuleBasedTriageAgent
from sentinel.triage.guardrails import InputSanitizer, OutputValidator
from sentinel.triage.tools import StaticAssetInventory, StaticThreatIntel, ToolRegistry

log = logging.getLogger("sentinel")


class Container:
    def __init__(self, settings: Settings | None = None, detectors=None) -> None:
        self.settings = settings or Settings()
        self.detectors = detectors or self._train()
        self.hooks: list[Callable[["Container"], None]] = []
        self._wire()

    def _train(self):
        s = self.settings
        norm = RawRecordNormalizer()
        train = SyntheticAttackRange(seed=s.seed + 1, n_benign=4000, attacks=SyntheticAttackRange.training_attacks(s.seed + 1, 30))
        events = [norm.normalize(r) for r in train.stream()]
        dets = [FlowDetector(FlowFeatures(), s), AuthDetector(AuthFeatures(), s), EndpointDetector(EndpointFeatures(), s)]
        for d in dets:
            d.fit(events)
        return dets

    def add_hook(self, fn: Callable[["Container"], None]) -> None:
        self.hooks.append(fn); fn(self)

    def reset(self) -> None:
        self._wire()

    def _wire(self) -> None:
        s = self.settings
        for d in self.detectors:
            d.reset()
        self.bus, self.audit, self.clock = InMemoryBus(), SqliteAuditLog(s.audit_db_path), SimClock()
        self.store, self.alerts, self.actions = InMemoryEventStore(), InMemoryRepository(), InMemoryRepository()
        self.reports: dict = {}
        self.correlator = EntityGraphCorrelator(s.correlation_window_s)
        self.baseline = RuleBaseline()
        assets, intel, san = StaticAssetInventory(), StaticThreatIntel(), InputSanitizer()
        self.sanitizer = san
        self.executors = [MockEdrExecutor(), MockIdentityExecutor(), MockFirewallExecutor(), MockTicketExecutor()]
        self.orchestrator = ResponseOrchestrator(RiskPolicy(assets, s.auto_execute_min_confidence), self.executors,
                                                 self.actions, self.audit, self.bus, s)
        self.agent = self._build_agent(assets, intel, san)
        ingest = IngestService(RawRecordNormalizer(), self.store, self.bus, self.clock)
        detect = DetectionService(self.detectors, self.alerts, self.bus, self.audit)
        correlate = CorrelationService(self.store, AttackMapper(), self.correlator, self.bus)
        triage = TriageService(self.agent, self.reports, self.orchestrator, self.audit, s)
        base = BaselineService(self.baseline)
        self.bus.subscribe("raw.events", ingest.on_raw)
        self.bus.subscribe("events", detect.on_event)
        self.bus.subscribe("events", base.on_event)
        self.bus.subscribe("alerts", correlate.on_alert)
        self.bus.subscribe("incidents", triage.on_incident)
        self.pipeline = SentinelPipeline(self.bus)
        self.evaluator = Evaluator(s)
        for fn in self.hooks:
            fn(self)

    def _build_agent(self, assets, intel, san):
        rules = RuleBasedTriageAgent(self.store, assets)
        if not self.settings.use_llm:
            return rules
        try:
            import anthropic
            tools = ToolRegistry(self.store, intel, assets, san)
            return LLMTriageAgent(anthropic.Anthropic(), self.settings.llm_model, tools, san, OutputValidator(), rules, self.store)
        except ImportError:
            log.warning("anthropic package missing; using rule-based triage")
            return rules

    # ---- convenience used by the demo, API and tests ----
    def run_scenario(self, which: str = "both", n_benign: int = 3000) -> int:
        src = SyntheticAttackRange(seed=self.settings.seed, n_benign=n_benign, attacks=SyntheticAttackRange.demo_attacks(which))
        return self.pipeline.run(src)

    def evaluate(self) -> dict:
        return self.evaluator.evaluate(self.store.all(), self.alerts.all(), self.correlator.incidents(),
                                       self.baseline.alerts, self.actions.all())
