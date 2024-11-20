class DBTraceModule:
    TABLE_NAME = "Modules"
    PATH_COLUMN_NAME = "Path"
    NAME_COLUMN_NAME = "Name"

    def __init__(self, space: 'DBTraceModuleSpace', tree: 'DBTraceAddressSnapRangePropertyMapTree[DBTraceModule, ?]', store: 'DBCachedObjectStore[?]', record):
        self.space = space
        super().__init__(tree, store, record)

    @property
    def path(self) -> str:
        return self._path

    @path.setter
    def path(self, value: str):
        if self._path == value:
            return
        self._path = value
        self.update()

    @property
    def name(self) -> str:
        return self._name

    @name.setter
    def name(self, value: str):
        if self._name == value:
            return
        self._name = value
        self.update()

    def update(self):
        pass  # Nothing to do here.

    @property
    def trace(self) -> 'DBTrace':
        return self.space.trace

    def add_section(self, section_path: str, section_name: str, range: AddressRange) -> 'DBTraceSection':
        with LockHold.lock(self.space.manager.write_lock()):
            return self.space.manager.do_add_section(self, section_path, section_name, range)

    @property
    def path_(self) -> str:
        with LockHold.lock(self.space.manager.read_lock()):
            return self.path

    def set_name(self, value: str):
        with LockHold.lock(self.space.manager.write_lock()):
            if self.name == value:
                return
            self.name = value
            self.update()
            self.space.trace.set_changed(TraceChangeRecord(TraceModuleChangeType.CHANGED, None, self))

    @property
    def name_(self) -> str:
        with LockHold.lock(self.space.manager.read_lock()):
            return self.name

    def set_range(self, range: AddressRange):
        with LockHold.lock(self.space.manager.write_lock()):
            if self.range == range:
                return
            do_set_range(range)
            self.space.trace.set_changed(TraceChangeRecord(TraceModuleChangeType.CHANGED, self.space, self))

    @property
    def base_(self) -> 'Address':
        with LockHold.lock(self.space.manager.read_lock()):
            return self.range.min_address

    def set_base(self, value: 'Address'):
        with LockHold.lock(self.space.manager.write_lock()):
            set_range(DBTraceUtils.to_range(value, self.range.max_address))

    @property
    def max_address_(self) -> 'Address':
        with LockHold.lock(self.space.manager.read_lock()):
            return self.range.max_address

    def set_max_address(self, value: 'Address'):
        with LockHold.lock(self.space.manager.write_lock()):
            set_range(DBTraceUtils.to_range(self.range.min_address, value))

    @property
    def length_(self) -> int:
        with LockHold.lock(self.space.manager.read_lock()):
            return self.range.length

    def set_length(self, value: int):
        if value < 0:
            raise AddressOverflowException()
        with LockHold.lock(self.space.manager.write_lock()):
            address = self.range.min_address
            set_range(DBTraceUtils.to_range(address, address.add_no_wrap(value - 1)))

    @property
    def lifespan_(self) -> 'Range[Long]':
        return self.lifespan

    def set_lifespan(self, value: 'Range[Long]'):
        with LockHold.lock(self.space.manager.write_lock()):
            space_manager.check_module_path_conflicts(self, self.path, value)
            sections = list(get_sections())
            for section in sections:
                space_manager.check_section_path_conflicts(section, section.path, value)
            old_lifespan = self.lifespan
            do_set_lifespan(value)
            for section in sections:
                section.do_set_lifespan(value)
        self.space.trace.set_changed(TraceChangeRecord(TraceModuleChangeType.LIFESPAN_CHANGED, None, self, old_lifespan, value))

    @property
    def loaded_snap_(self) -> int:
        return DBTraceUtils.lower_endpoint(self.lifespan)

    def set_loaded_snap(self, value: int):
        with LockHold.lock(self.space.manager.write_lock()):
            set_lifespan(DBTraceUtils.to_range(value, DBTraceUtils.upper_endpoint(self.lifespan)))

    @property
    def unloaded_snap_(self) -> int:
        return DBTraceUtils.upper_endpoint(self.lifespan)

    def set_unloaded_snap(self, value: int):
        with LockHold.lock(self.space.manager.write_lock()):
            set_lifespan(DBTraceUtils.to_range(DBTraceUtils.lower_endpoint(self.lifespan), value))

    @property
    def sections_(self) -> 'Collection[DBTraceSection]':
        return self.space_manager.get_sections_by_module_id(self.key)

    def get_section_by_name(self, section_name: str):
        return self.space_manager.get_section_by_name(self.key, section_name)

    def delete(self):
        with LockHold.lock(self.space.manager.write_lock()):
            self.space_manager.do_delete_module(self)
