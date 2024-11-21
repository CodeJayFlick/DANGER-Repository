class DBTraceMemoryRegion:
    TABLE_NAME = "MemoryRegions"
    PATH_COLUMN_NAME = "Path"
    NAME_COLUMN_NAME = "Name"
    FLAGS_COLUMN_NAME = "Flags"

    def __init__(self, space: 'DBTraceMemorySpace', tree: 'DBTraceAddressSnapRangePropertyMapTree[DBTraceMemoryRegion]', store: 'DBCachedObjectStore<?>', record):
        super().__init__(tree, store, record)
        self.space = space

    @property
    def path(self) -> str:
        return self._path

    @path.setter
    def set_path(self, value: str):
        if hasattr(self, '_path'):
            del self._path
        self._path = value

    @property
    def name(self) -> str:
        return self._name

    @name.setter
    def set_name(self, value: str):
        if hasattr(self, '_name'):
            del self._name
        self._name = value

    @property
    def flags_byte(self) -> int:
        return self._flags_byte

    @flags_byte.setter
    def set_flags_byte(self, value: int):
        if hasattr(self, '_flags_byte'):
            del self._flags_byte
        self._flags_byte = value

    @property
    def space(self) -> 'DBTraceMemorySpace':
        return self._space

    @space.setter
    def set_space(self, value: 'DBTraceMemorySpace'):
        if hasattr(self, '_space'):
            del self._space
        self._space = value

    @staticmethod
    def table_name(space: 'DBTraceMemorySpace', thread_key: int) -> str:
        return DBTraceUtils.table_name(DBTraceMemoryRegion.TABLE_NAME, space, thread_key, 0)

    def fresh(self, created=False):
        super().fresh(created)
        if not created:
            self.flags.clear()
            for f in TraceMemoryFlag.values():
                if (self.flags_byte & f.get_bits()) != 0:
                    self.flags.add(f)

    @staticmethod
    def check_overlap_conflicts(lifespan: 'Range[Long]', range: 'AddressRange') -> None:
        overlap_conflicts = space.get_regions_intersecting(lifespan, range)
        for c in overlap_conflicts:
            if c == this:
                continue
            raise TraceOverlappedRegionException(overlap_conflicts)

    @staticmethod
    def check_path_conflicts(lifespan: 'Range[Long]', path: str) -> None:
        path_conflicts = space.manager.get_regions_with_path_in_lifespan(lifespan, path)
        for c in path_conflicts:
            if c == this:
                continue
            raise DuplicateNameException("Only one region with a given path may occupy the same snap")

    def set(self, path: str, name: str, flags: 'Collection[TraceMemoryFlag]'):
        self.path = path
        self.name = name
        self.flags_byte = 0
        self.flags.clear()
        for f in flags:
            self.flags_byte |= f.get_bits()
            self.flags.add(f)
        update(PATH_COLUMN_NAME, NAME_COLUMN_NAME, FLAGS_COLUMN_NAME)

    def get_trace(self) -> 'DBTrace':
        return space.trace

    @property
    def path_(self) -> str:
        try:
            with LockHold.lock(space.lock.read_lock()):
                return self.path
        except Exception as e:
            print(f"Error: {e}")

    def set_name_(self, value: str):
        try:
            with LockHold.lock(space.lock.write_lock()):
                if hasattr(self, '_name'):
                    del self._name
                self._name = value
                update(NAME_COLUMN_NAME)
                space.trace.update_views_change_block_name(this)
        except Exception as e:
            print(f"Error: {e}")

    @property
    def name_(self) -> str:
        try:
            with LockHold.lock(space.lock.read_lock()):
                return self.name
        except Exception as e:
            print(f"Error: {e}")

    # ... and so on for the rest of the methods.
