"""Central settings. Every tunable lives here so no other module hard-codes a number."""
from __future__ import annotations
import os
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Settings:
    seed: int = 42
    # detection
    alert_threshold: float = 0.5        # score above this raises an alert
    uncertain_upper: float = 0.7        # between threshold and this => flagged "uncertain"
    # correlation / triage
    correlation_window_s: int = 1800
    triage_min_severity: float = 0.7    # incident must reach this before the agent is called
    # response
    auto_execute_min_confidence: float = 0.6
    auto_action_latency_s: float = 5.0
    analyst_approval_delay_s: float = 180.0   # SIMULATED analyst reaction time in the demo
    # manual-baseline ASSUMPTIONS (replace with figures measured from your own analysts)
    manual_triage_min: float = 10.0
    manual_response_min: float = 30.0
    review_min_per_incident: float = 5.0
    approval_min_per_action: float = 1.0
    # infrastructure
    audit_db_path: str = ":memory:"
    llm_model: str = field(default_factory=lambda: os.getenv("SENTINEL_LLM_MODEL", "claude-sonnet-5-5"))
    use_llm: bool = field(default_factory=lambda: bool(os.getenv("ANTHROPIC_API_KEY")))
