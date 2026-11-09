import hashlib, json, sqlite3, threading, time
from sentinel.domain.interfaces import AuditLog
from sentinel.domain.models import AuditRecord

GENESIS = "0" * 64


class SqliteAuditLog(AuditLog):
    """Append-only, hash-chained log: each row's hash covers the previous row's hash,
    so editing or deleting any row breaks verification. Swap for PostgreSQL by writing another AuditLog."""

    def __init__(self, path: str = ":memory:") -> None:
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._lock = threading.Lock()
        self._conn.execute("CREATE TABLE IF NOT EXISTS audit(seq INTEGER PRIMARY KEY, ts REAL, actor TEXT, "
                           "action TEXT, payload TEXT, prev_hash TEXT, hash TEXT)")

    @staticmethod
    def _digest(prev: str, seq: int, ts: float, actor: str, action: str, payload: str) -> str:
        return hashlib.sha256(f"{prev}|{seq}|{ts!r}|{actor}|{action}|{payload}".encode()).hexdigest()

    def append(self, actor: str, action: str, payload: dict, ts: float | None = None) -> AuditRecord:
        body = json.dumps(payload, sort_keys=True, default=str)
        ts = time.time() if ts is None else float(ts)
        with self._lock:
            row = self._conn.execute("SELECT seq, hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
            seq, prev = (row[0] + 1, row[1]) if row else (1, GENESIS)
            digest = self._digest(prev, seq, ts, actor, action, body)
            self._conn.execute("INSERT INTO audit VALUES (?,?,?,?,?,?,?)", (seq, ts, actor, action, body, prev, digest))
            self._conn.commit()
        return AuditRecord(seq=seq, ts=ts, actor=actor, action=action, payload=json.loads(body),
                           prev_hash=prev, hash=digest)

    def verify(self) -> tuple[bool, int | None]:
        prev = GENESIS
        with self._lock:
            rows = self._conn.execute("SELECT seq, ts, actor, action, payload, prev_hash, hash FROM audit ORDER BY seq").fetchall()
        for seq, ts, actor, action, payload, prev_hash, h in rows:
            if prev_hash != prev or self._digest(prev, seq, ts, actor, action, payload) != h:
                return False, seq
            prev = h
        return True, None

    def all(self, limit: int = 500) -> list[AuditRecord]:
        with self._lock:
            rows = self._conn.execute("SELECT seq, ts, actor, action, payload, prev_hash, hash FROM audit "
                                      "ORDER BY seq DESC LIMIT ?", (limit,)).fetchall()
        return [AuditRecord(seq=r[0], ts=r[1], actor=r[2], action=r[3], payload=json.loads(r[4]),
                            prev_hash=r[5], hash=r[6]) for r in reversed(rows)]
