import pytest
from sentinel.config import Settings
from sentinel.domain.interfaces import ActionExecutor
from sentinel.domain.models import Decision, ProposedAction, TriageReport
from sentinel.infra.audit import SqliteAuditLog
from sentinel.infra.bus import InMemoryBus
from sentinel.infra.repositories import InMemoryRepository
from sentinel.response.orchestrator import ResponseOrchestrator
from sentinel.response.policy import RiskPolicy
from sentinel.triage.tools import StaticAssetInventory


class FakeExecutor(ActionExecutor):            # any ActionExecutor can be substituted (Liskov)
    def __init__(self): self.ran = []
    def supports(self, t): return True
    def execute(self, a): self.ran.append(a.type); return "ok"
    def rollback(self, a): self.ran.remove(a.type); return "undone"


def make():
    ex, audit = FakeExecutor(), SqliteAuditLog()
    s = Settings()
    orch = ResponseOrchestrator(RiskPolicy(StaticAssetInventory(), s.auto_execute_min_confidence), [ex],
                                InMemoryRepository(), audit, InMemoryBus(), s)
    rep = TriageReport(incident_id="inc-1", summary="s", severity="high", confidence=0.95, evidence_event_ids=["e"],
                       actions=[ProposedAction(type="tag_incident", target="inc-1"),
                                ProposedAction(type="isolate_host", target="ws-009")], produced_by="test")
    return orch, ex, audit, rep


def test_high_impact_never_runs_without_approval():
    orch, ex, audit, rep = make()
    orch.plan(rep, now=100.0)
    assert ex.ran == ["tag_incident"]                       # low impact ran, isolate_host did not
    (pending,) = orch.pending()
    assert pending.action.type == "isolate_host" and pending.decision is Decision.PENDING


def test_approve_reject_rollback_are_audited():
    orch, ex, audit, rep = make()
    orch.plan(rep, now=100.0)
    pid = orch.pending()[0].id
    orch.approve(pid, "analyst1", now=160.0)
    assert "isolate_host" in ex.ran
    orch.rollback(pid, "analyst1", now=200.0)
    assert "isolate_host" not in ex.ran
    with pytest.raises(ValueError):
        orch.approve(pid, "analyst1", now=300.0)             # cannot approve twice
    actions = [r.action for r in audit.all()]
    assert {"action_proposed", "approval_requested", "action_approved", "action_executed", "action_rolled_back"} <= set(actions)
    assert audit.verify()[0]


def test_low_confidence_report_blocks_even_low_impact_auto_run():
    orch, ex, audit, rep = make()
    rep.confidence = 0.2
    orch.plan(rep, now=1.0)
    assert ex.ran == [] and len(orch.pending()) == 2
