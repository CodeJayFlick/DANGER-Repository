class DBTraceBreakpointManager:
    NAME = "Breakpoint"

    def __init__(self, dbh, open_mode, lock, monitor, base_language, trace, thread_manager):
        self.lock = lock
        super().__init__(NAME, dbh, open_mode, lock, monitor, base_language, trace, thread_manager)
        self.load_spaces()

    def create_space(self, space, ent) -> 'DBTraceBreakpointSpace':
        return DBTraceBreakpointSpace(self, dbh, space, ent)

    def get_for_space(self, space: AddressSpace, create_if_absent=False):
        return super().get_for_space(space, create_if_absent)

    @property
    def read_lock(self) -> 'Lock':
        return self.lock.read_lock()

    @property
    def write_lock(self) -> 'Lock':
        return self.lock.write_lock()

    def check_duplicate_path(self, ignore: DBTraceBreakpoint, path: str, lifespan: Range):
        for pc in self.get_breakpoints_by_path(path):
            if pc == ignore:
                continue
            if not DBTraceUtils.intersect(lifespan, pc.lifespan):
                continue
            raise DuplicateNameException(f"A breakpoint having path '{path}' already exists within an overlapping snap")

    def add_breakpoint(self, path: str, lifespan: Range, range: AddressRange, threads: Collection[TraceThread], kinds: Collection[TraceBreakpointKind], enabled: bool, comment: str) -> 'DBTraceBreakpoint':
        self.check_duplicate_path(None, path, lifespan)
        return self.delegate_write(range.address_space, lambda m: m.add_breakpoint(path, lifespan, range, threads, kinds, enabled, comment))

    def get_all_breakpoints(self):
        return self.delegate_collection(self.get_active_memory_spaces(), lambda m: list(m.get_all_breakpoints()))

    def get_breakpoints_by_path(self, path: str) -> Collection['DBTraceBreakpoint']:
        return self.delegate_collection(self.get_active_memory_spaces(), lambda m: list(m.get_breakpoints_by_path(path)))

    def get_placed_breakpoint_by_path(self, snap: int, path: str):
        with LockHold.lock(self.read_lock()):
            breakpoint = next((b for b in self.get_breakpoints_by_path(path) if b.lifespan.contains(snap)), None)
            return breakpoint

    def get_breakpoints_at(self, snap: int, address: Address) -> Collection['DBTraceBreakpoint']:
        return self.delegate_read(address.address_space, lambda m: list(m.get_breakpoints_at(snap, address)), [])

    def get_breakpoints_intersecting(self, span: Range, range: AddressRange):
        return self.delegate_read(range.address_space, lambda m: list(m.get_breakpoints_intersecting(span, range)), [])
