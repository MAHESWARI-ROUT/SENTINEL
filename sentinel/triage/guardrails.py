"""Guardrails around the LLM: log text is untrusted data, and model output is validated before use."""
from __future__ import annotations
import re
from pydantic import ValidationError
from sentinel.domain.models import Incident, ProposedAction, TriageReport

ALLOWED_ACTIONS = {"tag_incident", "notify_analyst", "add_watchlist", "collect_forensics",
                   "isolate_host", "disable_account", "block_ip"}
SEVERITIES = {"low", "medium", "high", "critical"}
_INJECTION = re.compile(r"(ignore (all |any )?(previous|prior) |disregard .{0,20}instructions|system prompt|"
                        r"you are now|act as|approve (all|every)|disable (the )?(audit|logging|approval)|"
                        r"<\s*/?\s*(system|assistant)\s*>)", re.I)


class InputSanitizer:
    def __init__(self, max_len: int = 300) -> None:
        self.max_len, self.flagged = max_len, 0

    def clean(self, value):
        if not isinstance(value, str):
            return value
        text = "".join(ch for ch in value if ch.isprintable())[: self.max_len]
        if _INJECTION.search(text):
            self.flagged += 1
            return "[REDACTED: suspected prompt injection]"
        return text

    def clean_obj(self, obj):
        if isinstance(obj, dict):
            return {k: self.clean_obj(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self.clean_obj(v) for v in obj]
        return self.clean(obj)


class InvalidReport(ValueError):
    pass


class OutputValidator:
    """Rejects model output that cites unknown evidence, uses unlisted actions or targets things outside the incident."""

    def validate(self, data: dict, incident: Incident, produced_by: str, now: float = 0.0) -> TriageReport:
        try:
            valid_targets = {e.split(":", 1)[1] for e in incident.entities} | {incident.id}
            evidence = [i for i in data.get("evidence_event_ids", []) if i in set(incident.event_ids)]
            if not evidence:
                raise InvalidReport("no valid evidence ids")
            if data.get("severity") not in SEVERITIES:
                raise InvalidReport("bad severity")
            actions = []
            for a in data.get("actions", []):
                if a.get("type") not in ALLOWED_ACTIONS:
                    raise InvalidReport(f"action not allowed: {a.get('type')}")
                if a.get("target") not in valid_targets:
                    raise InvalidReport(f"target outside incident: {a.get('target')}")
                actions.append(ProposedAction(type=a["type"], target=a["target"], rationale=str(a.get("rationale", ""))[:300]))
            return TriageReport(incident_id=incident.id, summary=str(data["summary"])[:1200], severity=data["severity"],
                                confidence=min(max(float(data["confidence"]), 0.0), 1.0), evidence_event_ids=evidence,
                                actions=actions, produced_by=produced_by, ts=now)
        except (KeyError, TypeError, ValueError, ValidationError) as exc:
            raise InvalidReport(str(exc)) from exc
