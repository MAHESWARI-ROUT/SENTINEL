"""End-to-end CLI demo: python -m sentinel.demo [--scenario both|phishing|lateral|benign] [--no-approve]"""
import argparse, json, logging, time
from sentinel.container import Container
from sentinel.domain.models import Decision


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenario", default="both", choices=["both", "phishing", "lateral", "benign"])
    ap.add_argument("--no-approve", action="store_true", help="leave high-impact actions waiting for a human")
    args = ap.parse_args()
    logging.basicConfig(level=logging.WARNING)

    t = time.time(); c = Container(); print(f"Models trained in {time.time() - t:.1f}s (LLM triage: {'on' if c.settings.use_llm else 'off, rule-based'})")
    t = time.time(); n = c.run_scenario(args.scenario); print(f"Processed {n} events in {time.time() - t:.1f}s\n")

    for inc in sorted(c.correlator.incidents(), key=lambda i: i.first_ts):
        rep = c.reports.get(inc.id)
        print(f"[{inc.severity.upper():8}] {inc.id}  score={inc.severity_score}  alerts={len(inc.alert_ids)}  {', '.join(e for e in inc.entities)}")
        print("   ATT&CK:", ", ".join(sorted({f'{h.id} {h.name}' for h in inc.techniques})) or "-")
        if rep:
            print("   Summary:", rep.summary)
            for r in (a for a in c.actions.all() if a.incident_id == inc.id):
                print(f"   - {r.action.type:17} {r.action.target:16} impact={r.impact.value:4} -> {r.decision.value}")
        else:
            print("   (below triage threshold: waiting for corroboration, no action taken)")
        print()

    pending = c.orchestrator.pending()
    print(f"{len(pending)} high-impact actions awaiting analyst approval")
    if pending and not args.no_approve:
        for a in pending:   # simulated analyst reacts after the configured delay
            c.orchestrator.approve(a.id, "analyst1", a.proposed_at + c.settings.analyst_approval_delay_s)
        print("-> analyst1 approved them (simulated).")
    ok, bad = c.audit.verify()
    print(f"Audit log: {len(c.audit.all(10**6))} records, chain {'VALID' if ok else f'BROKEN at {bad}'}\n")
    print(json.dumps(c.evaluate(), indent=2))


if __name__ == "__main__":
    main()
