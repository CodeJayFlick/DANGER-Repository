from collections import abc as collection_abcs

class TraceThreadManager:
    def __init__(self):
        self._threads = {}

    def add_thread(self, path: str, display=None, lifespan=range(0)):
        if not isinstance(lifespan, range) or len(lifespan) == 1:
            raise ValueError("Lifespan must be a non-empty range")
        
        if path in self._threads and any(snap >= min(lifespan) for snap in self._threads[path].lifespan):
            raise DuplicateNameException(f"A thread with the given full name already exists within an overlapping snap")

        self._threads[path] = {"display": display, "lifespan": lifespan}

    def create_thread(self, path: str, creation_snap: int) -> None:
        if not isinstance(creation_snap, int):
            raise ValueError("Creation snap must be a non-negative integer")
        
        return self.add_thread(path, lifespan=range(min(range), max(range)))

    @property
    def all_threads(self) -> collection_abcs.Iterable[dict]:
        for thread in sorted(self._threads.values(), key=lambda x: min(x["lifespan"])):
            yield {"path": thread["path"], "display": thread.get("display"), "lifespan": list(thread["lifespan"])}

    def get_threads_by_path(self, path: str) -> collection_abcs.Iterable[dict]:
        for thread in sorted([t for t in self._threads.values() if t["path"] == path], key=lambda x: min(x["lifespan"])):
            yield {"path": thread["path"], "display": thread.get("display"), "lifespan": list(thread["lifespan"])}

    def get_live_thread_by_path(self, snap: int, path: str) -> dict:
        for thread in self._threads.values():
            if thread["path"] == path and any(snap >= s for s in thread["lifespan"]):
                return {"path": thread["path"], "display": thread.get("display"), "lifespan": list(thread["lifespan"])}

    def get_thread(self, key: int) -> dict:
        if not isinstance(key, int):
            raise ValueError("Key must be a non-negative integer")
        
        for thread in self._threads.values():
            if any(snap == key for snap in thread["lifespan"]):
                return {"path": thread["path"], "display": thread.get("display"), "lifespan": list(thread["lifespan"])}

    def get_live_threads(self, snap: int) -> collection_abcs.Iterable[dict]:
        for thread in sorted([t for t in self._threads.values() if any(snap >= s for s in t["lifespan"])], key=lambda x: min(x["lifespan"])):
            yield {"path": thread["path"], "display": thread.get("display"), "lifespan": list(thread["lifespan"])}

class DuplicateNameException(Exception):
    pass
