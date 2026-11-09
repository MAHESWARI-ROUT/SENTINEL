from __future__ import annotations
from sentinel.config import Settings
from sentinel.domain.interfaces import ActionExecutor, AuditLog, EventBus, Repository
from sentinel.domain.models import ActionRecord, Decision, TriageReport
from sentinel.response.policy import RiskPolicy


class ResponseOrchestrator:
    """Plans actions from a triage report, runs low-risk ones, queues high-impact ones for a human, and logs everything."""

    def __init__(self, policy: RiskPolicy, executors: list[ActionExecutor], actions: Repository, audit: AuditLog,
                 bus: EventBus, settings: Settings) -> None:
        self._policy, self._execs, self._repo, self._audit, self._bus, self._s = policy, executors, actions, audit, bus, settings

    def plan(self, report: TriageReport, now: float) -> list[ActionRecord]:
        existing = {(r.incident_id, r.action.type, r.action.target) for r in self._repo.all()
                    if r.decision not in (Decision.REJECTED, Decision.ROLLED_BACK)}
        created = []
        for action in report.actions:
            if (report.incident_id, action.type, action.target) in existing:
                continue
            rec = ActionRecord(incident_id=report.incident_id, action=action, impact=self._policy.impact(action),
                               decision=self._policy.decide(action, report.confidence), proposed_at=now)
            self._repo.save(rec)
            self._audit.append("sentinel", "action_proposed", {"id": rec.id, "type": action.type, "target": action.target,
                               "impact": rec.impact.value, "decision": rec.decision.value, "report_by": report.produced_by}, ts=now)
            if rec.decision is Decision.AUTO:
                self._run(rec, now + self._s.auto_action_latency_s, "sentinel-auto")
            else:
                self._audit.append("sentinel", "approval_requested", {"id": rec.id}, ts=now)
                self._bus.publish("actions", rec)
            created.append(rec)
        return created

    def approve(self, action_id: str, analyst: str, now: float) -> ActionRecord:
        rec = self._pending(action_id)
        rec.decision, rec.decided_by, rec.decided_at = Decision.APPROVED, analyst, now
        self._audit.append(analyst, "action_approved", {"id": rec.id}, ts=now)
        return self._run(rec, now, analyst)

    def reject(self, action_id: str, analyst: str, now: float, reason: str = "") -> ActionRecord:
        rec = self._pending(action_id)
        rec.decision, rec.decided_by, rec.decided_at = Decision.REJECTED, analyst, now
        self._audit.append(analyst, "action_rejected", {"id": rec.id, "reason": reason}, ts=now)
        self._bus.publish("actions", rec)
        return rec

    def rollback(self, action_id: str, analyst: str, now: float) -> ActionRecord:
        rec = self._repo.get(action_id)
        if rec is None or rec.decision is not Decision.EXECUTED:
            raise ValueError("only executed actions can be rolled back")
        result = self._executor_for(rec).rollback(rec.action)
        rec.decision, rec.result = Decision.ROLLED_BACK, result
        self._audit.append(analyst, "action_rolled_back", {"id": rec.id, "result": result}, ts=now)
        self._bus.publish("actions", rec)
        return rec

    def pending(self) -> list[ActionRecord]:
        return [r for r in self._repo.all() if r.decision is Decision.PENDING]

    # ---- internals ----
    def _pending(self, action_id: str) -> ActionRecord:
        rec = self._repo.get(action_id)
        if rec is None or rec.decision is not Decision.PENDING:
            raise ValueError("action is not awaiting approval")
        return rec

    def _executor_for(self, rec: ActionRecord) -> ActionExecutor:
        for ex in self._execs:
            if ex.supports(rec.action.type):
                return ex
        raise LookupError(f"no executor for {rec.action.type}")

    def _run(self, rec: ActionRecord, ts: float, actor: str) -> ActionRecord:
        try:
            rec.result = self._executor_for(rec).execute(rec.action)
            rec.decision, rec.executed_at = Decision.EXECUTED, ts
            self._audit.append(actor, "action_executed", {"id": rec.id, "result": rec.result}, ts=ts)
        except Exception as exc:
            rec.decision, rec.result = Decision.FAILED, str(exc)
            self._audit.append(actor, "action_failed", {"id": rec.id, "error": str(exc)}, ts=ts)
        self._bus.publish("actions", rec)
        return rec
