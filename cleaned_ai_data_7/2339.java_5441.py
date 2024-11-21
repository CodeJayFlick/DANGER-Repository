class DBTraceBreakpoint:
    TABLE_NAME = "Breakpoints"
    ENABLED_MASK = 128

    PATH_COLUMN = None
    NAME_COLUMN = None
    THREADS_COLUMN = None
    FLAGS_COLUMN = None
    COMMENT_COLUMN = None

    def __init__(self, space: 'DBTraceBreakpointSpace', tree: object, store: object, record: object):
        super().__init__(tree, store, record)
        self.space = space

    @property
    def path(self) -> str:
        return self._path

    @path.setter
    def path(self, value: str):
        if not isinstance(value, str):
            raise TypeError("Path must be a string")
        self._path = value

    @property
    def name(self) -> str:
        return self._name

    @name.setter
    def name(self, value: str):
        if not isinstance(value, str):
            raise TypeError("Name must be a string")
        self._name = value

    @property
    def thread_keys(self) -> list:
        return self._thread_keys

    @thread_keys.setter
    def thread_keys(self, value: list):
        if not all(isinstance(x, int) for x in value):
            raise TypeError("Thread keys must be integers")
        self._thread_keys = value

    @property
    def flags_byte(self) -> bytes:
        return self._flags_byte

    @flags_byte.setter
    def flags_byte(self, value: bytes):
        if not isinstance(value, int):
            raise TypeError("Flags byte must be an integer")
        self._flags_byte = value

    @property
    def comment(self) -> str:
        return self._comment

    @comment.setter
    def comment(self, value: str):
        if not isinstance(value, str):
            raise TypeError("Comment must be a string")
        self._comment = value

    def __init__(self, space: 'DBTraceBreakpointSpace', tree: object, store: object, record: object):
        super().__init__(tree, store, record)
        self.space = space
        self.kinds = set()
        self.enabled = False

    @property
    def kinds(self) -> set:
        return self._kinds

    @kind.setter
    def kinds(self, value: set):
        if not isinstance(value, set):
            raise TypeError("Kinds must be a set")
        self._kinds = value

    @property
    def enabled(self) -> bool:
        return self._enabled

    @enabled.setter
    def enabled(self, value: bool):
        if not isinstance(value, bool):
            raise TypeError("Enabled must be a boolean")
        self._enabled = value

    def fresh(self, created: bool):
        super().fresh(created)
        if created:
            return
        do_fresh()

    def do_fresh(self):
        self.kinds.clear()
        for k in TraceBreakpointKind.values():
            if (self.flags_byte & k.get_bits()) != 0:
                self.kinds.add(k)
        self.enabled = (self.flags_byte & ENABLED_MASK) != 0

    @property
    def trace(self) -> 'DBTrace':
        return self.space.trace

    def set(self, path: str, name: str, threads: list, kinds: set, enabled: bool, comment: str):
        if not isinstance(threads, (list, set)):
            raise TypeError("Threads must be a list or set")
        for t in threads:
            if not isinstance(t, DBTraceThread):
                raise TypeError("Each thread must be an instance of DBTraceThread")

        self.path = path
        self.name = name
        self.thread_keys = [t.key() for t in threads]
        self.flags_byte = 0
        self.kinds.clear()
        for k in kinds:
            if isinstance(k, TraceBreakpointKind):
                self.flags_byte |= k.get_bits()
                self.kinds.add(k)
        if enabled:
            self.flags_byte |= ENABLED_MASK
        self.comment = comment

    def set(self, path: str, name: str, thread_keys: list, flags_byte: bytes, comment: str):
        self.path = path
        self.name = name
        self.thread_keys = [int(x) for x in thread_keys]
        self.flags_byte = flags_byte
        self.comment = comment

    def get_path(self) -> str:
        with LockHold.lock(self.space.lock.read_lock()):
            return self.path

    def set_name(self, value: str):
        with LockHold.lock(self.space.lock.write_lock()):
            self.name = value
            update(NAME_COLUMN)

    @property
    def name(self) -> str:
        with LockHold.lock(self.space.lock.read_lock()):
            return self.name

    def get_threads(self) -> set:
        with LockHold.lock(self.space.lock.read_lock()):
            if not self.thread_keys:
                return set()
            thread_manager = self.space.trace.get_thread_manager()
            threads = LinkedHashSet([thread_manager.get_thread(int(x)) for x in self.thread_keys])
            return unmodifiable_set(threads)

    def get_range(self) -> object:
        with LockHold.lock(self.space.lock.read_lock()):
            return range

    @property
    def min_address(self) -> Address:
        with LockHold.lock(self.space.lock.read_lock()):
            return range.get_min_address()

    @property
    def max_address(self) -> Address:
        with LockHold.lock(self.space.lock.read_lock()):
            return range.get_max_address()

    @property
    def length(self) -> int:
        with LockHold.lock(self.space.lock.read_lock()):
            return range.get_length()

    def set_lifespan(self, new_lifespan: Range):
        old_lifespan = None
        try:
            if not lifespan.contains(new_lifespan.lower_endpoint()):
                raise ValueError("snap must be within the current lifespan")
            do_set_lifespan(new_lifespan)
        except DuplicateNameException as e:
            print(f"Duplicate name exception caught: {e}")
        finally:
            space.trace.set_changed(TraceChangeRecord(TraceBreakpointChangeType.LIFESPAN_CHANGED, self.space, self))

    def get_placed_snap(self) -> int:
        with LockHold.lock(self.space.lock.read_lock()):
            return DBTraceUtils.lower_endpoint(lifespan)

    def set_cleared_snap(self, cleared_snap: bytes):
        set_lifespan(DBTraceUtils.to_range(get_placed_snap(), cleared_snap - 1))

    @property
    def cleared_snap(self) -> int:
        with LockHold.lock(self.space.lock.read_lock()):
            return DBTraceUtils.upper_endpoint(lifespan)

    def do_copy(self) -> 'DBTraceBreakpoint':
        breakpoint = space.breakpoint_map_space.put(self, None)
        breakpoint.set(path, name, thread_keys, flags_byte, comment)
        return breakpoint

    @property
    def kinds_view(self) -> set:
        with LockHold.lock(self.space.lock.read_lock()):
            return self.kinds

    def split_and_set(self, snap: int, enabled: bool, kinds: set):
        that = None
        old_lifespan = None
        new_lifespan = None
        try:
            if not lifespan.contains(snap):
                raise ValueError("snap must be within the current lifespan")
            if flags_byte == compute_flags_byte(enabled, kinds):
                return self

            if snap == get_placed_snap():
                do_set_flags(enabled, kinds)
                that = self
            else:
                that = do_copy()
                that.set_lifespan(DBTraceUtils.to_range(snap, cleared_snap))
                old_lifespan = lifespan
                new_lifespan = DBTraceUtils.to_range(get_placed_snap(), snap - 1)

        except DuplicateNameException as e:
            print(f"Duplicate name exception caught: {e}")
        finally:
            space.trace.set_changed(TraceChangeRecord(TraceBreakpointChangeType.ADDED, self.space, that))
            if old_lifespan is not None and new_lifespan is not None:
                space(trace).set_changed(TraceChangeRecord(TraceBreakpointChangeType.LIFESPAN_CHANGED, self.space, self))

        return that

    @staticmethod
    def compute_flags_byte(enabled: bool, kinds: set) -> bytes:
        flags = 0
        for k in kinds:
            if isinstance(k, TraceBreakpointKind):
                flags |= k.get_bits()
        if enabled:
            flags |= ENABLED_MASK
        return flags

    def do_set_flags(self, enabled: bool, kinds: set):
        self.flags_byte = compute_flags_byte(enabled, kinds)
        self.kinds.clear()
        for k in kinds:
            if isinstance(k, TraceBreakpointKind):
                self.kinds.add(k)
        self.enabled = enabled
        update(FLAGS_COLUMN)

    def do_set_enabled(self, enabled: bool):
        self.enabled = enabled
        if enabled:
            flags_byte |= ENABLED_MASK
        else:
            flags_byte &= ~ENABLED_ MASK

        update(FLAG_COLUMN)

    @property
    def comment(self) -> str:
        with LockHold.lock(self.space.lock.read_lock()):
            return self.comment

    @comment.setter
    def comment(self, value: str):
        if not isinstance(value, str):
            raise TypeError("Comment must be a string")
        self._comment = value
        update(COMMENT_COLUMN)

    def delete(self) -> None:
        space.delete_breakpoint(self)
