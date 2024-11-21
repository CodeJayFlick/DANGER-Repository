class UndefinedDBTraceData:
    def __init__(self, trace: 'ghidra.trace.database.DBTrace', snap: int, address: 'ghidra.program.model.address.Address', thread: 'ghidra.trace.database.thread.DBTraceThread', frame_level: int):
        self._trace = trace
        self._snap = snap
        self._lifespan = (self._snap, self._snap)
        self._address = address
        self._thread = thread
        self._frame_level = frame_level

    def get_trace_space(self) -> 'ghidra.trace.model.TraceAddressSpace':
        return self

    def get_address_space(self) -> 'ghidra.program.model.address.AddressSpace':
        return self._address.get_address_space()

    def delete(self):
        raise Exception("Cannot delete an undefined code unit")

    @property
    def trace(self) -> 'ghidra.trace.database.DBTrace':
        return self._trace

    @property
    def language(self) -> 'ghidra.program.model.lang.Language':
        return self._trace.get_base_language()

    def get_range(self):
        # TODO: Cache this?
        return AddressRangeImpl(self.min_address, self.max_address)

    def get_bounds(self):
        # TODO: Cache this?
        return ImmutableTraceAddressSnapRange(self.min_address, self.max_address, self.lifespan)

    @property
    def lifespan(self) -> 'range':
        return self._lifespan

    @property
    def start_snap(self) -> int:
        return self._snap

    def set_end_snap(self, end_snap: int):
        raise Exception("Cannot modify lifespan of default data unit")

    @property
    def end_snap(self) -> int:
        return self._snap

    @property
    def address(self) -> 'ghidra.program.model.address.Address':
        return self._address

    @property
    def thread(self) -> 'ghidra.trace.database.thread.DBTraceThread':
        return self._thread

    @property
    def frame_level(self) -> int:
        return self._frame_level

    @property
    def length(self) -> int:
        return 1

    @property
    def max_address(self) -> 'ghidra.program.model.address.Address':
        return self._address

    def __str__(self):
        return self.do_to_string()

    def get_address(self, op_index: int) -> 'ghidra.program.model.address.Address':
        # I should think an undefined data unit never presents an address, or operand
        # for that matter....
        return None

    def get_bytes(self, buffer: bytearray, address_offset: int):
        mem = self._trace.get_memory_manager().get(self, False)
        if mem is None:
            # TODO: 0-fill instead? Will need to check memory space bounds.
            return 0
        return mem.get_bytes(self.start_snap, self.address.add(address_offset), buffer)

    def is_defined(self) -> bool:
        return False

    @property
    def data_type(self):
        return DataType.DEFAULT

    @property
    def base_data_type(self):
        return DataType.DEFAULT

    def get_field_name(self) -> str:
        return None

    def get_path_name(self) -> str:
        return self.get_primary_symbol_or_dynamic_name()

    def get_component_path_name(self) -> str:
        return None

    @property
    def parent(self) -> 'ghidra.program.model.data.Data':
        return None

    @property
    def root(self) -> 'UndefinedDBTraceData':
        return self

    @property
    def root_offset(self) -> int:
        return 0

    @property
    def parent_offset(self) -> int:
        return 0

    def get_component(self, index: int):
        return None

    def get_component(self, component_path: list[int]):
        if component_path is None or len(component_path) == 0:
            return self
        return None

    @property
    def component_path(self) -> list[int]:
        return []

    @property
    def num_components(self) -> int:
        return 0

    def get_component_at(self, offset: int):
        return None

    def get_component_containing(self, offset: int):
        return None

    def get_components_containing(self, offset: int):
        if offset < 0 or offset >= self.length:
            return []
        return []

    @property
    def primitive_at(self, offset: int) -> 'UndefinedDBTraceData':
        if offset < 0 or offset >= self.length:
            return None
        return self

    @property
    def component_index(self) -> int:
        return -1

    @property
    def component_level(self) -> int:
        return 0

    def get_settings_space(self, create_if_absent: bool):
        return self._trace.get_data_settings_adapter().get(self, create_if_absent)

    @property
    def default_settings(self) -> 'ghidra.docking.settings.Settings':
        return DataType.DEFAULT.default_settings()
