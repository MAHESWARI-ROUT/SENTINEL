"""Pure data contracts passed between stages (the 'payloads' on the architecture slide)."""
from __future__ import annotations
import uuid
from enum import Enum
from typing import Any
from pydantic import BaseModel, Field


def new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


class EventKind(str, Enum):
    FLOW = "flow"
    AUTH = "auth"
    ENDPOINT = "endpoint"


class Impact(str, Enum):
    LOW = "low"
    HIGH = "high"


class Decision(str, Enum):
    AUTO = "auto"
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXECUTED = "executed"
    ROLLED_BACK = "rolled_back"
    FAILED = "failed"


class Event(BaseModel):
    """Normalized event {time, user, host, ip, attrs}."""
    id: str = Field(default_factory=lambda: new_id("evt"))
    ts: float
    kind: EventKind
    user: str | None = None
    host: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    attrs: dict[str, Any] = Field(default_factory=dict)
    quality_flags: list[str] = Field(default_factory=list)
    # Ground truth. Used ONLY by training and evaluation, never by detectors at inference.
    is_malicious: bool = False
    scenario: str | None = None


class Alert(BaseModel):
    """Alert {entity, score, confidence}."""
    id: str = Field(default_factory=lambda: new_id("alt"))
    event_id: str
    ts: float
    detector: str
    score: float
    confidence: float
    uncertain: bool = False
    user: str | None = None
    host: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    features: dict[str, float] = Field(default_factory=dict)
    reason: str = ""


class TechniqueHit(BaseModel):
    id: str
    name: str
    tactic: str
    alert_id: str


class Incident(BaseModel):
    """Incident {alerts, ATT&CK, timeline}."""
    id: str = Field(default_factory=lambda: new_id("inc"))
    entities: list[str] = Field(default_factory=list)
    alert_ids: list[str] = Field(default_factory=list)
    event_ids: list[str] = Field(default_factory=list)
    techniques: list[TechniqueHit] = Field(default_factory=list)
    severity_score: float = 0.0
    severity: str = "low"
    first_ts: float
    last_ts: float
    timeline: list[str] = Field(default_factory=list)


class ProposedAction(BaseModel):
    type: str
    target: str
    rationale: str = ""


class TriageReport(BaseModel):
    """Report {severity, evidence, action}."""
    incident_id: str
    summary: str
    severity: str
    confidence: float
    evidence_event_ids: list[str]
    actions: list[ProposedAction]
    produced_by: str
    ts: float = 0.0


class ActionRecord(BaseModel):
    id: str = Field(default_factory=lambda: new_id("act"))
    incident_id: str
    action: ProposedAction
    impact: Impact
    decision: Decision
    proposed_at: float
    decided_by: str | None = None
    decided_at: float | None = None
    executed_at: float | None = None
    result: str | None = None


class AuditRecord(BaseModel):
    seq: int
    ts: float
    actor: str
    action: str
    payload: dict[str, Any]
    prev_hash: str
    hash: str


class BaselineAlert(BaseModel):
    rule_id: str
    title: str
    event_id: str
    ts: float
