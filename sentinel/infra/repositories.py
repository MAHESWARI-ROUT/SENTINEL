import threading
from collections import defaultdict
from typing import Any
from sentinel.domain.interfaces import EventStore, Repository
from sentinel.domain.models import Event


class InMemoryRepository(Repository):
    def __init__(self) -> None:
        self._items: dict[str, Any] = {}
        self._lock = threading.RLock()

    def save(self, obj: Any) -> None:
        with self._lock:
            self._items[obj.id] = obj

    def get(self, obj_id: str) -> Any | None:
        return self._items.get(obj_id)

    def all(self) -> list[Any]:
        with self._lock:
            return list(self._items.values())


class InMemoryEventStore(EventStore):
    """Events indexed by user, host and IP so the triage agent's search_logs tool is fast."""

    def __init__(self) -> None:
        self._by_id: dict[str, Event] = {}
        self._index: dict[str, list[Event]] = defaultdict(list)

    def add(self, event: Event) -> None:
        self._by_id[event.id] = event
        for key in {event.user, event.host, event.src_ip, event.dst_ip} - {None}:
            self._index[key].append(event)

    def get(self, event_id: str) -> Event | None:
        return self._by_id.get(event_id)

    def search(self, entity: str, since: float | None = None, until: float | None = None, limit: int = 50) -> list[Event]:
        items = [e for e in self._index.get(entity, [])
                 if (since is None or e.ts >= since) and (until is None or e.ts <= until)]
        return items[:limit]

    def all(self) -> list[Event]:
        return list(self._by_id.values())
