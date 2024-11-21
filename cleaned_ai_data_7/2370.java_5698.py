class DBTraceCodeSpace:
    def __init__(self, manager: 'DBTraceCodeManager', dbh: 'DBHandle', space: 'AddressSpace',
                 ent: 'DBTraceSpaceEntry') -> None:
        self.manager = manager
        self.dbh = dbh
        self.space = space
        self.lock = manager.get_lock()
        self.base_language = manager.get_base_language()
        self.trace = manager.get_trace()
        self.data_type_manager = manager.data_type_manager
        self.reference_manager = manager.reference_manager
        self.all = AddressRangeImpl(space.get_min_address(), space.get_max_address())

        factory = trace.get_store_factory()

        thread_key = ent.get_thread_key()
        frame_level = ent.get_frame_level()

        self.instruction_map_space = DBTraceAddressSnapRangePropertyMapSpace(
            DBTraceInstruction.table_name(self.space, thread_key), factory, lock,
            self.space, DBTraceInstruction.__class__, lambda t, s, r: DBTraceInstruction(self, t, s, r)
        )
        self.data_map_space = DBTraceAddressSnapRangePropertyMapSpace(
            DBTraceData.table_name(self.space, thread_key, frame_level), factory, lock,
            self.space, DBTraceData.__class__, lambda t, s, r: DBTraceData(self, t, s, r)
        )

        self.instructions = create_instructions_view()
        self.defined_data = create_defined_data_view()
        self.undefined_data = create_undefined_data_view()
        self.data = create_data_view()
        self.code_units = create_code_units_view()

    def clear_language(self, span: 'Range[Long]', range: 'AddressRange', lang_key: int,
                        monitor: 'TaskMonitor') -> None:
        monitor.set_message("Clearing instructions")
        monitor.set_maximum(len(instruction_map_space))
        for instruction in instruction_map_space.values():
            if lang_key != self.manager.proto_store.get_object_at(
                    instruction.get_prototype_key()).get_language_key():
                continue
            instruction_map_space.delete_data(instruction)
            self.instructions.unit_removed(instruction)

    def invalidate_cache(self) -> None:
        with lock.write_lock() as hold:
            self.instruction_map_space.invalidate_cache()
            self.instructions.invalidate_cache()

            self.data_map_space.invalidate_cache()
            self.defined_data.invalidate_cache()

            self.undefined_data.invalidate_cache()

    @property
    def address_space(self):
        return self.space

    @property
    def thread(self) -> 'DBTraceThread':
        return None

    @property
    def frame_level(self) -> int:
        return 0

    @property
    def code_units_view(self) -> 'DBTraceCodeUnitsView':
        return self.code_units

    @property
    def instructions_view(self) -> 'DBTraceInstructionsView':
        return self.instructions

    @property
    def data_view(self) -> 'DBTraceDataView':
        return self.data

    @property
    def defined_data_view(self) -> 'DBTraceDefinedDataView':
        return self.defined_data

    @property
    def undefined_data_view(self) -> 'DBTraceUndefinedDataView':
        return self.undefined_data

    def bytes_changed(self, changed: set['TraceAddressSnapRange'], snap: int,
                      start: 'Address', old_bytes: bytearray, new_bytes: bytearray) -> None:
        diffs = ByteArrayUtils.compute_diffs_address_set(start, old_bytes, new_bytes)
        affected_units = set()
        for box in changed:
            if not diffs.intersects(box.get_x1(), box.get_x2()):
                continue
            for unit in self.defined_units_view.get_intersecting(box):
                if diffs.intersects(unit.min_address, unit.max_address):
                    affected_units.add(unit)

        new_buf = ByteMemBufferImpl(start, new_bytes,
                                     self.trace.base_language.is_big_endian())
        for unit in affected_units:
            # Rule: Break unit down into time portions before affected range, and at/within range
            # For Data in affected range:
            #     For dynamic types, only accept if the length is unaffected
            #     For simple types, just re-apply
            # For Instruction in affected range:
            #     Probably just delete it.
            unit_start_snap = None
            unit_end_snap = unit.end_snap
            if unit.start_snap < snap:
                unit.set_end_snap(snap - 1)
                unit_start_snap = snap
            else:
                unit_start_snap = unit.start_snap
                unit.delete()
            if isinstance(unit, DBTraceData):
                data_unit = DBTraceData(unit)
                re_apply = False
                data_type = data_unit.data_type
                if isinstance(data_type, Dynamic):
                    ddt = Dynamic(data_type)
                    new_wrapped = WrappedMemBuffer(new_buf,
                                                    int(data_unit.address - start))
                    new_length = ddt.length(new_wrapped, data_unit.length())
                    re_apply = new_length == unit.length()
                else:
                    re_apply = True
                if re_apply:
                    try:
                        self.defined_data_view.create(DBTraceUtils.to_range(unit_start_snap,
                                                                              unit_end_snap),
                                                      unit.address, data_type, unit.length())
                    except CodeUnitInsertionException as e:
                        raise AssertionError(e)

    def create_instructions_view(self) -> 'DBTraceInstructionsView':
        return DBTraceInstructionsView(self)

    def create_defined_data_view(self) -> 'DBTraceDefinedDataView':
        return DBTraceDefinedDataView(self)

    def create_undefined_data_view(self) -> 'DBTraceUndefinedDataView':
        return DBTraceUndefinedDataView(self)

    def create_data_view(self) -> 'DBTraceDataView':
        return DBTraceDataView(self)

    def create_code_units_view(self) -> 'DBTraceCodeUnitsView':
        return DBTraceCodeUnitsView(self)
