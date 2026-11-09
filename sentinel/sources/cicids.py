"""Replays a real CIC-IDS2017 CSV (e.g. the 'MachineLearningCVE' files) as raw flow records."""
import hashlib
import pandas as pd
from sentinel.domain.interfaces import EventSource
from sentinel.sources.synthetic import BASE_TS, _ext_ip
import numpy as np


class CicIdsCsvSource(EventSource):
    COLS = {"Flow Duration": "dur_us", "Total Fwd Packets": "fp", "Total Backward Packets": "bp",
            "Total Length of Fwd Packets": "fb", "Total Length of Bwd Packets": "bb",
            "Destination Port": "port", "Label": "label"}

    def __init__(self, path: str, limit: int = 20000) -> None:
        self.path, self.limit = path, limit

    def stream(self):
        df = pd.read_csv(self.path, nrows=self.limit, skipinitialspace=True)
        df.columns = [c.strip() for c in df.columns]
        rng = np.random.RandomState(0)
        for i, row in enumerate(df.to_dict("records")):
            src = row.get("Source IP") or "10.0.1." + str(int(hashlib.md5(str(i // 50).encode()).hexdigest(), 16) % 200 + 1)
            dst = row.get("Destination IP") or _ext_ip(rng)
            label = str(row.get("Label", "BENIGN"))
            yield {"source": "cicids", "type": "flow", "ts": BASE_TS + i * 0.5, "user": None, "host": None,
                   "src_ip": src, "dst_ip": dst,
                   "data": {"duration_ms": row["Flow Duration"] / 1000.0, "fwd_pkts": row["Total Fwd Packets"],
                            "bwd_pkts": row["Total Backward Packets"], "fwd_bytes": row["Total Length of Fwd Packets"],
                            "bwd_bytes": row["Total Length of Bwd Packets"], "dst_port": row["Destination Port"]},
                   "_truth": {"malicious": label.upper() != "BENIGN", "scenario": None if label.upper() == "BENIGN" else label}}
