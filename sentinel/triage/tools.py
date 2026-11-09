"""Tools the triage agent may call. It gets read-only access; there is no tool that changes anything."""
from __future__ import annotations
from datetime import datetime, timezone
from sentinel.domain.interfaces import AssetInventory, EventStore, ThreatIntel
from sentinel.triage.guardrails import InputSanitizer


class StaticThreatIntel(ThreatIntel):
    BAD = {"185.199.110.9": "known C2 infrastructure", "91.92.109.43": "bulk-exfil drop site",
           "203.0.113.77": "credential-stuffing source"}

    def lookup(self, ip: str) -> dict:
        return {"ip": ip, "reputation": "malicious" if ip in self.BAD else "unknown", "note": self.BAD.get(ip, "")}


class StaticAssetInventory(AssetInventory):
    DB = {"srv-db": {"role": "database", "criticality": "critical"}, "srv-file": {"role": "file server", "criticality": "high"},
          "srv-patch": {"role": "patch management", "criticality": "medium"},
          "scanner-01": {"role": "vulnerability scanner", "criticality": "low", "note": "authorised scanner"},
          "vpn-gw": {"role": "vpn gateway", "criticality": "high"}, "mail-gw": {"role": "mail gateway", "criticality": "high"}}

    def context(self, host: str) -> dict:
        return {"host": host, **self.DB.get(host, {"role": "workstation", "criticality": "low"})}


class ToolRegistry:
    def __init__(self, store: EventStore, intel: ThreatIntel, assets: AssetInventory, sanitizer: InputSanitizer) -> None:
        self._store, self._intel, self._assets, self._san = store, intel, assets, sanitizer
        self._fns = {"search_logs": self._search, "lookup_intel": lambda ip: self._intel.lookup(ip),
                     "get_asset": lambda host: self._assets.context(host)}

    def specs(self) -> list[dict]:
        obj = lambda k, d: {"type": "object", "properties": {k: {"type": "string", "description": d}}, "required": [k]}
        return [{"name": "search_logs", "description": "Recent events for a user, host or IP", "input_schema": obj("entity", "user, host or ip value")},
                {"name": "lookup_intel", "description": "Threat-intel reputation for an IP", "input_schema": obj("ip", "IP address")},
                {"name": "get_asset", "description": "Role and criticality of a host", "input_schema": obj("host", "host name")}]

    def call(self, name: str, args: dict):
        if name not in self._fns:
            return {"error": "unknown tool"}
        return self._san.clean_obj(self._fns[name](*args.values()))

    def _search(self, entity: str):
        return [{"id": e.id, "time": datetime.fromtimestamp(e.ts, timezone.utc).strftime("%H:%M:%S"), "kind": e.kind.value,
                 "user": e.user, "host": e.host, "attrs": e.attrs} for e in self._store.search(entity, limit=15)]
