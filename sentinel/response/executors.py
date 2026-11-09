"""Mock connectors standing in for EDR, identity provider, firewall and ticketing. Replace each with a real
API client implementing ActionExecutor; nothing else changes (Liskov: they are interchangeable)."""
from sentinel.domain.interfaces import ActionExecutor
from sentinel.domain.models import ProposedAction


class MockEdrExecutor(ActionExecutor):
    def __init__(self) -> None:
        self.isolated: set[str] = set(); self.forensics: set[str] = set()

    def supports(self, t): return t in {"isolate_host", "collect_forensics"}

    def execute(self, a: ProposedAction) -> str:
        (self.isolated if a.type == "isolate_host" else self.forensics).add(a.target)
        return f"EDR: {a.type} on {a.target}"

    def rollback(self, a: ProposedAction) -> str:
        self.isolated.discard(a.target); self.forensics.discard(a.target)
        return f"EDR: released {a.target}"


class MockIdentityExecutor(ActionExecutor):
    def __init__(self) -> None:
        self.disabled: set[str] = set()

    def supports(self, t): return t == "disable_account"
    def execute(self, a): self.disabled.add(a.target); return f"IdP: disabled account {a.target}"
    def rollback(self, a): self.disabled.discard(a.target); return f"IdP: re-enabled account {a.target}"


class MockFirewallExecutor(ActionExecutor):
    def __init__(self) -> None:
        self.blocked: set[str] = set()

    def supports(self, t): return t == "block_ip"
    def execute(self, a): self.blocked.add(a.target); return f"Firewall: blocked {a.target}"
    def rollback(self, a): self.blocked.discard(a.target); return f"Firewall: unblocked {a.target}"


class MockTicketExecutor(ActionExecutor):
    def __init__(self) -> None:
        self.log: list[str] = []

    def supports(self, t): return t in {"tag_incident", "notify_analyst", "add_watchlist"}
    def execute(self, a): self.log.append(f"{a.type}:{a.target}"); return f"Ticketing: {a.type} {a.target}"
    def rollback(self, a): return "nothing to roll back"
