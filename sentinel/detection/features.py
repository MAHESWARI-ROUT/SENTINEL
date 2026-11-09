"""Feature extractors, one per event kind (Strategy). Flow features use a sliding window per source IP."""
import math, re
from collections import Counter, defaultdict, deque
from sentinel.domain.interfaces import FeatureExtractor
from sentinel.domain.models import Event

OFFICE = {"outlook.exe", "winword.exe", "excel.exe"}
SHELLS = {"powershell.exe", "cmd.exe", "wscript.exe"}
REMOTE_EXEC = {"psexec.exe", "psexesvc.exe"}
_ENC = re.compile(r"\s-e(nc|ncodedcommand)?\s", re.I)


def is_internal(ip: str | None) -> bool:
    return bool(ip) and ip.startswith("10.")


def hour_of(ts: float) -> float:
    return (ts % 86400) / 3600


def entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


class FlowFeatures(FeatureExtractor):
    names = ["log_duration", "fwd_pkts", "bwd_pkts", "log_fwd_bytes", "log_bwd_bytes", "pkts_per_s",
             "smb_port", "dst_external", "fanout_60s", "syn_only"]

    def __init__(self, window_s: float = 60.0) -> None:
        self._w, self._recent = window_s, defaultdict(deque)

    def reset(self) -> None:
        self._recent.clear()

    def extract(self, e: Event) -> list[float]:
        a, dq = e.attrs, self._recent[e.src_ip]
        while dq and e.ts - dq[0][0] > self._w:
            dq.popleft()
        dq.append((e.ts, e.dst_ip))
        fanout = len({d for _, d in dq})
        pkts = a["fwd_pkts"] + a["bwd_pkts"]
        return [math.log1p(a["duration_ms"]), a["fwd_pkts"], a["bwd_pkts"], math.log1p(a["fwd_bytes"]),
                math.log1p(a["bwd_bytes"]), min(pkts / max(a["duration_ms"] / 1000, 0.001), 1e5),
                float(a["dst_port"] == 445), float(not is_internal(e.dst_ip)), float(fanout), float(a["bwd_pkts"] == 0)]


class AuthFeatures(FeatureExtractor):
    names = ["success", "failed_1h", "log_geo_km", "new_device", "night"]

    def reset(self) -> None:
        pass

    def extract(self, e: Event) -> list[float]:
        a, h = e.attrs, hour_of(e.ts)
        return [float(bool(a["success"])), float(a.get("failed_1h", 0)), math.log1p(a.get("geo_km", 0.0)),
                float(bool(a.get("new_device", False))), float(h < 6 or h >= 22)]


class EndpointFeatures(FeatureExtractor):
    names = ["log_cmd_len", "cmd_entropy", "has_enc", "parent_office", "child_shell", "remote_exec", "night"]

    def reset(self) -> None:
        pass

    def extract(self, e: Event) -> list[float]:
        a = e.attrs
        cmd, proc, parent = a.get("cmdline", ""), a["process"].lower(), a.get("parent", "").lower()
        h = hour_of(e.ts)
        return [math.log1p(len(cmd)), entropy(cmd), float(bool(_ENC.search(cmd))), float(parent in OFFICE),
                float(proc in SHELLS), float(proc in REMOTE_EXEC), float(h < 6 or h >= 22)]
