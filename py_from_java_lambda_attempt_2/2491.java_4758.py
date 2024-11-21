Here is the translation of the given Java code into equivalent Python:

```Python
class DBTraceThread:
    TABLE_NAME = "Threads"
    PATH_COLUMN_NAME = "Path"
    NAME_COLUMN_NAME = "Name"
    CREATION_SNAP_COLUMN_NAME = "CreatedAt"
    DESTRUCTION_SNAP_COLUMN_NAME = "DestroyedAt"
    COMMENT_COLUMN_NAME = "Comment"

    def __init__(self, manager):
        self.manager = manager
        self.path = None
        self.name = None
        self.creation_snap = 0
        self.destruction_snap = 0
        self.lifespan = None

    def set(self, path: str, name: str, lifespan: range) -> None:
        self.path = path
        self.name = name
        self.creation_snap = min(lifespan)
        self.destruction_snap = max(lifespan)

    @property
    def trace(self):
        return self.manager.trace

    @property
    def path_(self):
        with self.manager.lock.read_lock():
            return self.path

    @path_.setter
    def set_path_(self, value: str) -> None:
        with self.manager.lock.write_lock():
            self.path = value
            self.manager.trace.set_changed(TraceThreadChangeType.CHANGED, self)

    @property
    def name_(self):
        with self.manager.lock.read_lock():
            return self.name

    @name_.setter
    def set_name_(self, value: str) -> None:
        with self.manager.lock.write_lock():
            self.name = value
            self.manager.trace.set_changed(TraceThreadChangeType.CHANGED, self)

    @property
    def creation_snap_(self):
        return self.creation_snap

    @creation_snap_.setter
    def set_creation_snap_(self, value: int) -> None:
        with self.manager.lock.write_lock():
            self.lifespan = range(value, self.destruction_snap)
            self.manager.trace.set_changed(TraceThreadChangeType.LIFESPAN_CHANGED, self)

    @property
    def destruction_snap_(self):
        return self.destruction_snap

    @destruction_snap_.setter
    def set_destruction_snap_(self, value: int) -> None:
        with self.manager.lock.write_lock():
            self.lifespan = range(self.creation_snap_, value)
            self.manager.trace.set_changed(TraceThreadChangeType.LIFESPAN_CHANGED, self)

    @property
    def lifespan_(self):
        return self.lifespan

    @lifespan_.setter
    def set_lifespan_(self, value: range) -> None:
        with self.manager.lock.write_lock():
            if not isinstance(value, range):
                raise TypeError("Lifespan must be a range")
            self.creation_snap_ = min(value)
            self.destruction_snap_ = max(value)

    @property
    def comment(self):
        return self.comment_

    @comment.setter
    def set_comment_(self, value: str) -> None:
        with self.manager.lock.write_lock():
            self.comment_ = value

    def delete(self) -> None:
        self.manager.delete_thread(self)
```

Please note that this is a direct translation of the given Java code into Python. It may not be perfect and might require some adjustments to work correctly in your specific use case.