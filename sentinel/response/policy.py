from __future__ import annotations
from sentinel.domain.interfaces import AssetInventory
from sentinel.domain.models import Decision, Impact, ProposedAction

LOW_IMPACT = {"tag_incident", "notify_analyst", "add_watchlist", "collect_forensics"}


class RiskPolicy:
    """Decides what may run unattended. Anything that can interrupt a user or a system is HIGH impact and
    ALWAYS needs a human, whatever the model's confidence."""

    def __init__(self, assets: AssetInventory, auto_min_confidence: float) -> None:
        self._assets, self._min = assets, auto_min_confidence

    def impact(self, action: ProposedAction) -> Impact:
        return Impact.LOW if action.type in LOW_IMPACT else Impact.HIGH

    def decide(self, action: ProposedAction, report_confidence: float) -> Decision:
        if self.impact(action) is Impact.LOW and report_confidence >= self._min:
            return Decision.AUTO
        return Decision.PENDING
