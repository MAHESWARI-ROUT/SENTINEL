import logging
from collections import defaultdict
from typing import Any
from sentinel.domain.interfaces import EventBus, Handler

log = logging.getLogger("sentinel.bus")


class InMemoryBus(EventBus):
    """Synchronous pub/sub with named topics (raw.events, events, alerts, incidents, actions).
    A Redis Streams / Kafka class implementing EventBus can replace this without touching any service."""

    def __init__(self) -> None:
        self._subs: dict[str, list[Handler]] = defaultdict(list)

    def subscribe(self, topic: str, handler: Handler) -> None:
        self._subs[topic].append(handler)

    def publish(self, topic: str, message: Any) -> None:
        for handler in list(self._subs[topic]):
            try:
                handler(message)
            except Exception:  # one bad record must not kill the stream
                log.exception("handler failed on topic %s", topic)
