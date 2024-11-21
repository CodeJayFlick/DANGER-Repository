import logging
from typing import Dict, List, Any

class PullSnapshotHandler:
    def __init__(self,
                 result_ref: 'AtomicReference[Dict[int, Any]]',
                 node: Any,
                 slots: List[int],
                 factory: Any) -> None:
        self.result_ref = result_ref
        self.node = node
        self.slots = slots
        self.factory = factory

    def on_complete(self, response: Dict[int, bytes]) -> None:
        with self.result_ref.lock:
            ret = {}
            for slot, snapshot_bytes in response.items():
                snapshot = self.factory.create()
                snapshot.deserialize(snapshot_bytes)
                ret[slot] = snapshot
            self.result_ref.set(ret)

    def on_error(self, exception: Exception) -> None:
        logging.error("Cannot pull snapshot of {} from {}".format(len(self.slots), self.node), exception)
        with self.result_ref.lock:
            self.result_ref.notify_all()

class AtomicReference:
    def __init__(self, value=None):
        self.value = value
        self._lock = threading.Lock()

    @property
    def lock(self):
        return self._lock

    def set(self, value):
        with self._lock:
            self.value = value

    def notify_all(self):
        with self._lock:
            thread.allocate_lock().notify_all()
