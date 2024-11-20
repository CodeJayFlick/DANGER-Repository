class DBTraceModuleSpace:
    def __init__(self, manager: 'DBTraceModuleManager', space: 'AddressSpace') -> None:
        self.manager = manager
        self.space = space
        self.lock = manager.get_lock()
        self.trace = manager.get_trace()

        self.module_map_space = DBTraceAddressSnapRangePropertyMapSpace(
            DBTraceModule.table_name(space), 
            trace.get_store_factory(), 
            lock, 
            space, 
            DBTraceModule.__class__, 
            lambda t, s, r: DBTraceModule(self, t, s, r)
        )
        
        self.modules_by_path = module_map_space.get_user_index(str, DBTraceModule.PATH_COLUMN)
        self.module_view = frozenset(module_map_space.values())

        self.section_map_space = DBTraceAddressSnapRangePropertyMapSpace(
            DBTraceSection.table_name(space), 
            trace.get_store_factory(), 
            lock, 
            space, 
            DBTraceSection.__class__, 
            lambda t, s, r: DBTraceSection(self, t, s, r)
        )
        
        self.sections_by_module_key = section_map_space.get_user_index(int, DBTraceSection.MODULE_COLUMN)
        self.sections_by_path = section_map_space.get_user_index(str, DBTraceSection.PATH_COLUMN)
        self.section_view = frozenset(section_map_space.values())

    def get_thread(self) -> 'DBTraceThread':
        return None

    def get_frame_level(self) -> int:
        return 0

    def invalidate_cache(self):
        module_map_space.invalidate_cache()
        section_map_space.invalidate_cache()

    @property
    def address_space(self) -> 'AddressSpace':
        return self.space

    def do_add_module(self, module_path: str, module_name: str, range: 'AddressRange', lifespan: Range[int]) -> 'DBTraceModule':
        module = module_map_space.put(ImmutableTraceAddressSnapRange(range, lifespan), None)
        module.set(module_path, module_name)
        trace.set_changed(TraceChangeRecord(TraceModuleChangeType.ADDED, None, module))
        return module

    def get_all_modules(self) -> frozenset['DBTraceModule']:
        return self.module_view

    def do_get_modules_by_path(self, module_path: str) -> frozenset['DBTraceModule']:
        return self.modules_by_path.get(module_path)

    @property
    def loaded_modules(self, snap: int) -> frozenset['DBTraceModule']:
        return frozenset(module_map_space.reduce(TraceAddressSnapRangeQuery.at_snap(snap, self.space)).values())

    @property
    def modules_at(self, snap: int, address: 'Address') -> frozenset['DBTraceModule']:
        return frozenset(module_map_space.reduce(TraceAddressSnapRangeQuery.at(address, snap)).values())

    @property
    def modules_intersecting(self, lifespan: Range[int], range: 'AddressRange') -> frozenset['DBTraceModule']:
        return frozenset(module_map_space.reduce(TraceAddressSnapRangeQuery.intersecting(range, lifespan)).values())

    def do_add_section(self, module: 'DBTraceModule', section_path: str, section_name: str, range: 'AddressRange') -> 'DBTraceSection':
        section = section_map_space.put(ImmutableTraceAddressSnapRange(range, module.get_lifespan()), None)
        section.set(module, section_path, section_name)
        trace.set_changed(TraceChangeRecord(TraceSectionChangeType.ADDED, None, section))
        return section

    @property
    def all_sections(self) -> frozenset['DBTraceSection']:
        return self.section_view

    @property
    def sections_at(self, snap: int, address: 'Address') -> frozenset['DBTraceSection']:
        return frozenset(section_map_space.reduce(TraceAddressSnapRangeQuery.at(address, snap)).values())

    @property
    def sections_intersecting(self, lifespan: Range[int], range: 'AddressRange') -> frozenset['DBTraceSection']:
        return frozenset(section_map_space.reduce(TraceAddressSnapRangeQuery.intersecting(range, lifespan)).values())

    def do_get_sections_by_module_id(self, key: int) -> frozenset['DBTraceSection']:
        return self.sections_by_module_key.get(key)

    def do_get_section_by_name(self, module_key: int, section_name: str) -> 'DBTraceSection':
        for section in self.sections_by_module_key.get(module_key):
            if not Objects.equals(section.name, section_name):
                continue
            return section

        return None

    def do_get_sections_by_path(self, section_path: str) -> frozenset['DBTraceSection']:
        return self.sections_by_path.get(section_path)

    def do_get_module_by_id(self, module_key: int) -> 'DBTraceModule':
        return module_map_space.data_by_key(module_key)
