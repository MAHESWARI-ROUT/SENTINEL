"""Synthetic attack range: benign background + benign 'noise' that fools simple rules + two attack scenarios.
Records are RAW dicts (what a log shipper would send), not Event objects."""
from __future__ import annotations
import numpy as np
from sentinel.domain.interfaces import EventSource

_MIDNIGHT = 1_700_000_000 - (1_700_000_000 % 86400)
BASE_TS = float(_MIDNIGHT + 8 * 3600)          # 08:00 UTC
USERS = ["asha", "bala", "charu", "dev", "esha", "farid", "gita", "hari", "priya", "arun"]
FILE_SRV, DB_SRV, BACKUP_SRV, AUTH_SRV = "10.0.2.10", "10.0.2.20", "10.0.2.30", "10.0.2.5"
C2_IP, EXFIL_IP, ATTACKER_IP = "185.199.110.9", "91.92.109.43", "203.0.113.77"
BENIGN_PROCS = [("chrome.exe", "explorer.exe", "chrome.exe --profile-directory=Default"),
                ("outlook.exe", "explorer.exe", "outlook.exe /recycle"),
                ("excel.exe", "explorer.exe", "excel.exe report.xlsx"),
                ("cmd.exe", "explorer.exe", "cmd /c dir"),
                ("powershell.exe", "explorer.exe", "powershell Get-Process"),
                ("chrome.exe", "outlook.exe", "chrome.exe https://intranet.corp/policy")]
_B64 = np.array(list("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"))


def _identity(user: str) -> tuple[str, str]:
    i = USERS.index(user)
    return f"ws-{i + 1:03d}", f"10.0.1.{i + 1}"


def _rec(ts, typ, user=None, host=None, src_ip=None, dst_ip=None, truth=(False, None), **data) -> dict:
    return {"source": typ, "type": typ, "ts": float(ts), "user": user, "host": host, "src_ip": src_ip,
            "dst_ip": dst_ip, "data": data, "_truth": {"malicious": truth[0], "scenario": truth[1]}}


def _ext_ip(rng) -> str:
    return f"142.250.{rng.randint(0, 255)}.{rng.randint(1, 254)}"


class SyntheticAttackRange(EventSource):
    def __init__(self, seed: int = 1, n_benign: int = 3000, attacks: list[tuple[str, str, float]] | None = None,
                 noise: bool = True, start_ts: float = BASE_TS) -> None:
        self.seed, self.n_benign, self.noise, self.start = seed, n_benign, noise, start_ts
        self.attacks = attacks or []

    # ---- ready-made attack lists -------------------------------------------------------------
    @staticmethod
    def demo_attacks(which: str = "both") -> list[tuple[str, str, float]]:
        plan = {"phishing": [("phishing", "priya", 4 * 3600)], "lateral": [("lateral", "arun", 5 * 3600)],
                "both": [("phishing", "priya", 4 * 3600), ("lateral", "arun", 5 * 3600)], "benign": []}
        return plan[which]

    @staticmethod
    def training_attacks(seed: int, n: int = 30) -> list[tuple[str, str, float]]:
        rng = np.random.RandomState(seed)
        return [(sc, USERS[rng.randint(len(USERS))], float(rng.uniform(600, 7 * 3600)))
                for sc in ("phishing", "lateral") for _ in range(n)]

    # ---- EventSource -------------------------------------------------------------------------
    def stream(self):
        rng = np.random.RandomState(self.seed)
        recs = self._benign(rng)
        if self.noise:
            recs += self._noise(rng)
        for scenario, user, offset in self.attacks:
            recs += getattr(self, f"_{scenario}")(rng, user, self.start + offset)
        recs.sort(key=lambda r: r["ts"])
        yield from recs

    # ---- generators --------------------------------------------------------------------------
    def _benign(self, rng) -> list[dict]:
        out = []
        for _ in range(self.n_benign):
            user = USERS[rng.randint(len(USERS))]
            host, ip = _identity(user)
            ts, r = self.start + rng.uniform(0, 8 * 3600), rng.rand()
            if r < 0.6:
                port = int(rng.choice([443, 80, 53, 445], p=[.7, .1, .1, .1]))
                dst = FILE_SRV if port == 445 else _ext_ip(rng)
                out.append(_rec(ts, "flow", user, host, ip, dst, duration_ms=float(rng.lognormal(7, 1)),
                                fwd_pkts=int(1 + rng.poisson(8)), bwd_pkts=int(1 + rng.poisson(10)),
                                fwd_bytes=int(rng.lognormal(8, 1)), bwd_bytes=int(rng.lognormal(9, 1)), dst_port=port))
            elif r < 0.8:
                out.append(_rec(ts, "auth", user, host, ip, AUTH_SRV, success=True, failed_1h=int(rng.rand() < .05),
                                geo_km=float(rng.exponential(10)), new_device=bool(rng.rand() < .02)))
            else:
                proc, parent, cmd = BENIGN_PROCS[rng.randint(len(BENIGN_PROCS))]
                out.append(_rec(ts, "endpoint", user, host, ip, None, process=proc, parent=parent, cmdline=cmd))
        return out

    def _noise(self, rng) -> list[dict]:
        """Benign activity that trips naive rules: typo logins, admin scripts, night backups, scanners."""
        out, s = [], self.start
        for k in range(6):                                           # typo'd passwords, then success
            u = USERS[rng.randint(len(USERS))]; h, ip = _identity(u)
            out.append(_rec(s + 1800 * (k + 1), "auth", u, h, ip, AUTH_SRV, success=True,
                            failed_1h=int(rng.randint(5, 7)), geo_km=float(rng.exponential(8)), new_device=False))
        for k in range(6):                                           # patch tooling using bypass flag
            out.append(_rec(s + 2400 * (k + 1), "endpoint", "svc_patch", "srv-patch", "10.0.2.40", None,
                            process="powershell.exe", parent="ccmexec.exe",
                            cmdline="powershell -ExecutionPolicy Bypass -File patch.ps1"))
        for k in range(4):                                           # nightly backup, 80 MB
            out.append(_rec(s - 6 * 3600 + k * 600, "flow", "svc_backup", "srv-file", FILE_SRV, BACKUP_SRV,
                            duration_ms=900000.0, fwd_pkts=60000, bwd_pkts=30000, fwd_bytes=80_000_000,
                            bwd_bytes=40_000, dst_port=445))
        for k in range(4):                                           # on-call engineer at 02:00
            out.append(_rec(s - 6 * 3600 + k * 900, "auth", "dev", "ws-004", "10.0.1.4", AUTH_SRV, success=True,
                            failed_1h=0, geo_km=3.0, new_device=False))
        for k in range(3):                                           # vulnerability scanner, SYN-only
            for j in range(12):
                out.append(_rec(s + 3000 * (k + 1) + j * 2, "flow", "scanner", "scanner-01", "10.0.2.99",
                                f"10.0.1.{j + 1}", duration_ms=2.0, fwd_pkts=1, bwd_pkts=0, fwd_bytes=60,
                                bwd_bytes=0, dst_port=445))
        return out

    def _phishing(self, rng, user: str, t0: float) -> list[dict]:
        host, ip = _identity(user); T = (True, "phishing"); out = []
        blob = "".join(rng.choice(_B64, 160))
        out.append(_rec(t0, "endpoint", user, host, ip, None, truth=T, process="powershell.exe", parent="outlook.exe",
                        cmdline=f"powershell -nop -w hidden -enc {blob}"))
        for i in range(6):                                           # C2 beacon every 60 s
            out.append(_rec(t0 + 30 + 60 * i, "flow", user, host, ip, C2_IP, truth=T, duration_ms=float(rng.uniform(55000, 60000)),
                            fwd_pkts=3, bwd_pkts=2, fwd_bytes=220, bwd_bytes=180, dst_port=443))
        out.append(_rec(t0 + 1500, "auth", user, "vpn-gw", ATTACKER_IP, AUTH_SRV, truth=T, success=True,
                        failed_1h=7, geo_km=7800.0, new_device=True))
        out.append(_rec(t0 + 1620, "auth", user, "mail-gw", ATTACKER_IP, AUTH_SRV, truth=T, success=True,
                        failed_1h=0, geo_km=7800.0, new_device=True))
        return out

    def _lateral(self, rng, user: str, t0: float) -> list[dict]:
        host, ip = _identity(user); T = (True, "lateral"); out = []
        out.append(_rec(t0, "endpoint", user, host, ip, None, truth=T, process="psexec.exe", parent="cmd.exe",
                        cmdline=f"psexec \\\\{FILE_SRV} -u svc_admin cmd.exe"))
        for i in range(12):                                          # SMB sessions to many hosts
            out.append(_rec(t0 + 10 + 3 * i, "flow", user, host, ip, f"10.0.1.{20 + i}", truth=T,
                            duration_ms=float(rng.uniform(120, 200)), fwd_pkts=4, bwd_pkts=3, fwd_bytes=500,
                            bwd_bytes=350, dst_port=445))
        out.append(_rec(t0 + 60, "endpoint", user, "srv-file", FILE_SRV, None, truth=T, process="psexesvc.exe",
                        parent="services.exe", cmdline="psexesvc.exe"))
        out.append(_rec(t0 + 90, "auth", user, "srv-db", ip, DB_SRV, truth=T, success=True, failed_1h=3, geo_km=0.0,
                        new_device=True))
        for i in range(3):                                           # exfiltration, ~150 MB each
            out.append(_rec(t0 + 300 + 20 * i, "flow", user, "srv-file", FILE_SRV, EXFIL_IP, truth=T, duration_ms=120000.0,
                            fwd_pkts=100000, bwd_pkts=2000, fwd_bytes=150_000_000, bwd_bytes=5000, dst_port=443))
        return out
