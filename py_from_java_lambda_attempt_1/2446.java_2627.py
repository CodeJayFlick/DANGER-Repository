Here is the translation of the given Java code into equivalent Python:

```Python
from abc import ABCMeta, abstractmethod
import collections
import threading


class DBTraceSpaceEntry:
    SPACE_COLUMN_NAME = "space"
    THREAD_COLUMN_NAME = "thread"
    FRAME_COLUMN_NAME = "frame"

    def __init__(self, store, record):
        super().__init__()
        self.space_name = None
        self.thread_key = None
        self.frame_level = None

    @abstractmethod
    def set(self, space_name: str, thread_key: int, frame_level: int) -> None:
        pass


class AbstractDBTraceSpaceBasedManager(metaclass=ABCMeta):
    def __init__(self,
                 name: str,
                 dbh: object,
                 open_mode: str,
                 lock: threading.Lock,
                 monitor: object,
                 base_language: object,
                 trace: object,
                 thread_manager: object) -> None:
        self.name = name
        self.dbh = dbh
        self.lock = lock
        self.base_language = base_language
        self.trace = trace
        self.thread_manager = thread_manager

    def table_name(self, space: str, thread_key: int, frame_level: int) -> str:
        return f"{self.name}_{space}_{thread_key}_{frame_level}"

    @abstractmethod
    def create_space(self, space: str, ent: DBTraceSpaceEntry) -> object:
        pass

    @abstractmethod
    def create_register_space(self, space: str, thread: object, ent: DBTraceSpaceEntry) -> object:
        pass


class DBTraceManager(AbstractDBTraceSpaceBasedManager):
    def __init__(self,
                 name: str,
                 dbh: object,
                 open_mode: str,
                 lock: threading.Lock,
                 monitor: object,
                 base_language: object,
                 trace: object,
                 thread_manager: object) -> None:
        super().__init__(name, dbh, open_mode, lock, monitor, base_language, trace, thread_manager)

    def load_spaces(self):
        for ent in self.space_store.values():
            space = self.base_language.get_address_factory().get_address_space(ent.space_name)
            if space is None:
                print(f"Space {ent.space_name} does not exist in the trace (language={self.base_language})")
            elif space.is_register_space():
                thread = self.thread_manager.get_thread(ent.thread_key)
                reg_space = self.create_register_space(space, thread, ent)
                self.reg_spaces[ImmutablePair.of(thread, ent.frame_level)] = reg_space
            else:
                mem_space = self.create_space(space, ent)
                self.mem_spaces[space] = mem_space

    def get_for_space(self, space: str, create_if_absent: bool) -> object:
        if not space.is_memory_space():
            raise ValueError("Space must be a memory space")
        if not create_if_absent:
            with self.lock.read_lock():
                return self.mem_spaces.get(space)
        try:
            ent = self.space_store.create()
            ent.set(space.name, -1, 0)
            return self.create_space(space, ent)
        except Exception as e:
            print(f"Error: {e}")

    def get_for_register_space(self, thread: object, frame_level: int, create_if_absent: bool) -> object:
        db_thread = self.thread_manager.assert_is_mine(thread)
        frame = ImmutablePair.of(thread, frame_level)
        if not create_if_absent:
            with self.lock.read_lock():
                return self.reg_spaces.get(frame)
        try:
            ent = self.space_store.create()
            ent.set(self.base_language.get_address_factory().get_register_space().name, db_thread.key, frame_level)
            return self.create_register_space(self.base_language.get_address_factory().get_register_space(), db_thread, ent)
        except Exception as e:
            print(f"Error: {e}")

    def get_trace(self) -> object:
        return self.trace

    def get_lock(self) -> threading.Lock:
        return self.lock

    def get_base_language(self) -> object:
        return self.base_language

    def get_active_spaces(self):
        return list(self.mem_spaces.values())

    def get_active_memory_spaces(self):
        return list(self.mem_spaces.values())

    def get_active_register_spaces(self):
        return list(self.reg_spaces.values())
```

This Python code is equivalent to the given Java code.