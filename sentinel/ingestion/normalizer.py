from __future__ import annotations
from sentinel.domain.interfaces import Normalizer
from sentinel.domain.models import Event, EventKind

REQUIRED = {EventKind.FLOW: ["src_ip", "dst_ip", "duration_ms", "fwd_pkts", "bwd_pkts", "fwd_bytes", "bwd_bytes", "dst_port"],
            EventKind.AUTH: ["user", "success"],
            EventKind.ENDPOINT: ["host", "process"]}
NON_NEGATIVE = ["duration_ms", "fwd_pkts", "bwd_pkts", "fwd_bytes", "bwd_bytes", "geo_km", "failed_1h"]


class RawRecordNormalizer(Normalizer):
    """Maps raw records to the common Event schema and attaches data-quality flags
    ('missing:<field>', 'suspicious:<why>') instead of silently dropping or trusting bad data."""

    def __init__(self, max_skew_s: float = 86400.0) -> None:
        self._max_skew, self._latest = max_skew_s, None

    def normalize(self, raw: dict) -> Event:
        kind = EventKind(raw["type"])
        attrs = dict(raw.get("data", {}))
        flat = {**{k: raw.get(k) for k in ("user", "host", "src_ip", "dst_ip")}, **attrs}
        flags = [f"missing:{f}" for f in REQUIRED[kind] if flat.get(f) is None]
        for f in NON_NEGATIVE:
            v = attrs.get(f)
            if isinstance(v, (int, float)) and v < 0:
                flags.append(f"suspicious:negative_{f}")
        ts = float(raw["ts"])
        if self._latest is not None and ts > self._latest + self._max_skew:
            flags.append("suspicious:clock_skew")
        else:
            self._latest = ts if self._latest is None else max(self._latest, ts)
        truth = raw.get("_truth", {})
        return Event(ts=ts, kind=kind, user=raw.get("user"), host=raw.get("host"), src_ip=raw.get("src_ip"),
                     dst_ip=raw.get("dst_ip"), attrs=attrs, quality_flags=flags,
                     is_malicious=bool(truth.get("malicious", False)), scenario=truth.get("scenario"))
