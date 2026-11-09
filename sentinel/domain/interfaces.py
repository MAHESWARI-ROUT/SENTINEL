"""Abstractions (the D in SOLID). High-level code depends on these, never on concrete classes.
Each interface is deliberately small (the I in SOLID)."""
from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Any, Callable, Iterator
from sentinel.domain.models import (Alert, ActionRecord, AuditRecord, BaselineAlert, Event, Incident,
                                    ProposedAction, TechniqueHit, TriageReport)

Handler = Callable[[Any], None]


class EventSource(ABC):
    @abstractmethod
    def stream(self) -> Iterator[dict]: ...


class Normalizer(ABC):
    @abstractmethod
    def normalize(self, raw: dict) -> Event: ...


class FeatureExtractor(ABC):
    @abstractmethod
    def extract(self, event: Event) -> list[float]: ...
    @abstractmethod
    def reset(self) -> None: ...
    names: list[str]


class Detector(ABC):
    name: str

    @abstractmethod
    def supports(self, event: Event) -> bool: ...
    @abstractmethod
    def detect(self, event: Event) -> Alert | None: ...
    def reset(self) -> None:  # optional hook for stateful detectors
        pass


class TechniqueRule(ABC):
    @abstractmethod
    def match(self, alert: Alert, event: Event) -> list[tuple[str, str, str]]:
        """Return [(technique_id, name, tactic)]."""


class Correlator(ABC):
    @abstractmethod
    def add(self, alert: Alert, hits: list[TechniqueHit], event: Event) -> Incident: ...
    @abstractmethod
    def incidents(self) -> list[Incident]: ...


class TriageAgent(ABC):
    @abstractmethod
    def triage(self, incident: Incident) -> TriageReport: ...


class ThreatIntel(ABC):
    @abstractmethod
    def lookup(self, ip: str) -> dict: ...


class AssetInventory(ABC):
    @abstractmethod
    def context(self, host: str) -> dict: ...


class ActionExecutor(ABC):
    @abstractmethod
    def supports(self, action_type: str) -> bool: ...
    @abstractmethod
    def execute(self, action: ProposedAction) -> str: ...
    @abstractmethod
    def rollback(self, action: ProposedAction) -> str: ...


class AuditLog(ABC):
    @abstractmethod
    def append(self, actor: str, action: str, payload: dict, ts: float | None = None) -> AuditRecord: ...
    @abstractmethod
    def verify(self) -> tuple[bool, int | None]: ...
    @abstractmethod
    def all(self, limit: int = 500) -> list[AuditRecord]: ...


class EventBus(ABC):
    @abstractmethod
    def publish(self, topic: str, message: Any) -> None: ...
    @abstractmethod
    def subscribe(self, topic: str, handler: Handler) -> None: ...


class EventStore(ABC):
    @abstractmethod
    def add(self, event: Event) -> None: ...
    @abstractmethod
    def get(self, event_id: str) -> Event | None: ...
    @abstractmethod
    def search(self, entity: str, since: float | None = None, until: float | None = None,
               limit: int = 50) -> list[Event]: ...
    @abstractmethod
    def all(self) -> list[Event]: ...


class Repository(ABC):
    """Tiny generic id->object store used for alerts, incidents, reports and actions."""
    @abstractmethod
    def save(self, obj: Any) -> None: ...
    @abstractmethod
    def get(self, obj_id: str) -> Any | None: ...
    @abstractmethod
    def all(self) -> list[Any]: ...
