"""Compares SENTINEL with the rule baseline on the same stream. Timing figures are SIMULATED seconds and the
manual-effort numbers come from Settings assumptions: state that clearly when you present results."""
from __future__ import annotations
from sentinel.config import Settings
from sentinel.domain.models import ActionRecord, Alert, BaselineAlert, Decision, Event, Incident

CONTAIN = {"isolate_host", "disable_account"}


class Evaluator:
    def __init__(self, settings: Settings) -> None:
        self.s = settings

    def evaluate(self, events: list[Event], alerts: list[Alert], incidents: list[Incident],
                 baseline: list[BaselineAlert], actions: list[ActionRecord]) -> dict:
        mal = {e.id for e in events if e.is_malicious}
        ben_total = max(len(events) - len(mal), 1)
        start: dict[str, float] = {}
        for e in events:
            if e.is_malicious and e.scenario:
                start[e.scenario] = min(start.get(e.scenario, e.ts), e.ts)
        actionable = [i for i in incidents if i.severity_score >= self.s.triage_min_severity]
        sent_flagged = {eid for i in actionable for eid in i.event_ids}
        base_flagged = {b.event_id for b in baseline}

        def stats(flagged: set[str], items: int, tp_items: int) -> dict:
            tp = len(flagged & mal)
            return {"analyst_items": items, "false_positive_items": items - tp_items,
                    "item_precision": round(tp_items / items, 3) if items else None,
                    "event_recall": round(tp / max(len(mal), 1), 3),
                    "false_positive_rate": round(len(flagged - mal) / ben_total, 5)}

        base_tp_items = sum(1 for b in baseline if b.event_id in mal)
        sent_tp_items = sum(1 for i in actionable if set(i.event_ids) & mal)
        out = {"baseline": stats(base_flagged, len(baseline), base_tp_items),
               "sentinel": stats(sent_flagged, len(actionable), sent_tp_items),
               "sentinel_raw_alerts": len(alerts), "incidents_total": len(incidents)}
        out["alert_volume_reduction_pct"] = round(100 * (1 - len(actionable) / max(len(baseline), 1)), 1)

        # --- time to detect / respond per scenario (simulated seconds from the first malicious event) ---
        queue = self._baseline_queue(baseline, mal)
        per = {}
        for sc, t0 in start.items():
            sc_events = {e.id for e in events if e.scenario == sc}
            inc = [i for i in actionable if set(i.event_ids) & sc_events]
            inc_ids = {i.id for i in inc}
            confirm = min((a.proposed_at for a in actions if a.incident_id in inc_ids), default=None)  # first triage
            contain = min((a.executed_at for a in actions if a.action.type in CONTAIN and a.executed_at is not None
                           and a.incident_id in inc_ids), default=None)
            b_confirm = min((t for eid, t in queue.items() if eid in sc_events), default=None)
            per[sc] = {"sentinel_mttd_s": None if confirm is None else round(confirm - t0, 1),
                       "sentinel_mttr_s": None if contain is None else round(contain - t0, 1),
                       "baseline_mttd_s": None if b_confirm is None else round(b_confirm - t0, 1),
                       "baseline_mttr_s": None if b_confirm is None else round(b_confirm + self.s.manual_response_min * 60 - t0, 1)}
        out["per_scenario"] = per
        approvals = sum(1 for a in actions if a.decided_by and a.decided_by != "sentinel-auto")
        out["analyst_minutes"] = {"baseline": round(len(baseline) * self.s.manual_triage_min, 1),
                                  "sentinel": round(len(actionable) * self.s.review_min_per_incident
                                                    + approvals * self.s.approval_min_per_action, 1)}
        out["assumptions"] = {"manual_triage_min": self.s.manual_triage_min, "manual_response_min": self.s.manual_response_min,
                              "analyst_approval_delay_s": self.s.analyst_approval_delay_s}
        return out

    def _baseline_queue(self, baseline: list[BaselineAlert], mal: set[str]) -> dict[str, float]:
        """One analyst works the baseline alerts first-in-first-out; returns when each TRUE alert gets confirmed."""
        free, done = 0.0, {}
        for b in sorted(baseline, key=lambda b: b.ts):
            begin = max(b.ts, free)
            free = begin + self.s.manual_triage_min * 60
            if b.event_id in mal and b.event_id not in done:
                done[b.event_id] = free
        return done
