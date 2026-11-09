# SENTINEL: agentic, human-in-the-loop cyber-resilience POC

Detect -> correlate -> explain -> respond, with a human approving every high-impact action and a tamper-evident audit log.
Runs fully offline on synthetic data (an optional loader replays real CIC-IDS2017 CSVs). An LLM triage agent is optional.

## Run it in VS Code
1. Install **Python 3.10+** and the **Python** extension (VS Code will suggest it).
2. `File > Open Folder...` and choose `sentinel_poc`.
3. Terminal > New Terminal, then:
   - Windows: `py -m venv .venv` then `.venv\Scripts\activate`
   - macOS/Linux: `python3 -m venv .venv` then `source .venv/bin/activate`
   - `pip install -r requirements.txt`
4. `Ctrl+Shift+P` > **Python: Select Interpreter** > pick `.venv`.
5. Run & Debug (`Ctrl+Shift+D`) > **SENTINEL: end-to-end demo** > press F5. It trains the models, replays both attacks,
   prints incidents, ATT&CK mapping, actions, the audit check and the SENTINEL vs baseline numbers.
6. Pick **SENTINEL: analyst console**, press F5, open http://127.0.0.1:8000, click *Run both attacks*, then Approve / Reject.
7. Testing icon (beaker) > run all tests, or `pytest -q` in the terminal.
8. Optional LLM triage: copy `.env.example` to `.env`, put your key in, run `set ANTHROPIC_API_KEY=...` (Windows) /
   `export ANTHROPIC_API_KEY=...` (macOS/Linux) before launching. LLM output is validated; if rejected, the rule agent answers.

## How the code maps to the architecture slide
| Stage | Code |
|---|---|
| Sources | `sources/synthetic.py`, `sources/cicids.py` |
| Ingest | `ingestion/normalizer.py` (schema + data-quality flags), `services.IngestService`, `infra/bus.py` |
| Detect | `detection/features.py`, `detection/detectors.py` (XGBoost + isotonic, Isolation Forest, autoencoder) |
| Correlate | `correlation/correlator.py` (NetworkX entity graph), `correlation/attack_map.py` (ATT&CK) |
| Triage | `triage/agents.py`, `triage/tools.py`, `triage/guardrails.py` |
| Respond | `response/policy.py`, `response/orchestrator.py`, `response/executors.py` |
| Storage / audit | `infra/audit.py` (hash chain), `infra/repositories.py` |
| Baseline / results | `baseline/rules.py`, `evaluation/metrics.py` |
| Console | `api/app.py` (REST + WebSocket), `api/static/index.html` |
| Wiring | `container.py` (the only file that names concrete classes) |

## SOLID in this codebase
- **S**: one job per class: `RawRecordNormalizer` only normalizes, `InputSanitizer` only sanitizes, `RiskPolicy` only decides, `SqliteAuditLog` only audits.
- **O**: add a detector (subclass `ScoringDetector`), an ATT&CK rule (`AttackMapper.register`), a baseline `Rule`, or an executor without editing existing classes.
- **L**: any `ActionExecutor`, `TriageAgent`, `AuditLog` or `EventBus` can replace another (`tests/test_response.py` swaps in a fake executor).
- **I**: small interfaces in `domain/interfaces.py`; e.g. executors can't read the audit log, detectors can't execute actions.
- **D**: services depend on those abstractions; `container.py` injects the concrete classes.

## Swapping in production parts
- Redis Streams / Kafka: implement `EventBus` (publish/subscribe) and change one line in `container._wire`.
- PostgreSQL: implement `AuditLog`, `EventStore`, `Repository`.
- Real EDR / IdP / firewall / SOAR: implement `ActionExecutor` for each (see `response/executors.py`).
- Splunk / Sentinel / Wazuh: write an `EventSource` that yields raw dicts.
- React console: the REST + `/ws` API is ready; `api/static/index.html` is a no-build placeholder.

## Be upfront about these limits when you present
- Data is synthetic; detection numbers show the pipeline works, not real-world accuracy. Use `CicIdsCsvSource` for the public-dataset claim.
- MTTD / MTTR are in **simulated seconds**. Baseline times come from a one-analyst queue using the assumptions in `config.py` (10 min per alert, 30 min to respond). Replace them with figures you can justify.
- Models and calibration thresholds are tuned on the same synthetic generator (different seed). Re-tune on real data.
- The executors are mocks, and the Redis/Kafka and PostgreSQL pieces are interfaces with in-memory/SQLite implementations.
