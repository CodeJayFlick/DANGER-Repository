class DBTraceReferenceManager:
    def __init__(self, dbh, open_mode, lock, monitor, base_language, trace, thread_manager, overlay_adapter):
        self.overlay_adapter = overlay_adapter
        super().__init__("Reference", dbh, open_mode, lock, monitor, base_language, trace, thread_manager)

    def create_space(self, space, ent) -> 'DBTraceReferenceSpace':
        return DBTraceReferenceSpace(self, dbh, space, ent)

    def create_register_space(self, space, thread, ent) -> 'DBTraceReferenceRegisterSpace':
        return DBTraceReferenceRegisterSpace(self, dbh, space, ent, thread)

    def check_is_in_memory(self, space):
        if not space.is_memory_space():
            raise ValueError("Address must be in memory.")

    def get_for_space(self, space, create_if_absent) -> 'DBTraceReferenceSpace':
        return super().get_for_space(space, create_if_absent)

    def read_lock(self) -> Lock:
        return self.lock.read_lock()

    def write_lock(self) -> Lock:
        return self.lock.write_lock()

    def do_add_xref(self, entry):
        if not entry.to_address.is_memory_address():
            return
        space = self.get_reference_space(entry.to_address.address_space(), True)
        space.do_add_xref(entry)

    def do_del_xref(self, entry):
        if not entry.to_address.is_memory_address():
            return
        space = self.get_reference_space(entry.to_address.address_space(), False)
        assert space is not None
        space.do_del_xref(entry)

    def do_set_xref_lifespan(self, entry):
        if not entry.to_address.is_memory_address():
            return
        space = self.get_reference_space(entry.to_address.address_space(), False)
        assert space is not None
        space.do_set_xref_lifespan(entry)

    def assert_is_mine(self, ref) -> 'DBTraceReference':
        if not isinstance(ref, DBTraceReference):
            raise ValueError("Given reference is not in this trace")
        db_ref = DBTraceReference(ref)
        if db_ref.ent.space.manager != self:
            raise ValueError("Given reference is not in this trace")
        return db_ref

    def get_reference_space(self, space, create_if_absent) -> 'DBTraceReferenceSpace':
        return super().get_for_space(space, create_if_absent)

    def add_reference(self, ref):
        return delegate_write(ref.from_address.address_space(), lambda s: s.add_reference(ref))

    def add_memory_reference(self, lifespan, from_address, to_address, ref_type, source, operand_index) -> 'DBTraceReference':
        return delegate_write(from_address.address_space(), lambda s: s.add_memory_reference(lifespan, from_address, to_address, ref_type, source, operand_index))

    def get_reference(self, snap, from_address, to_address, operand_index):
        return delegate_read(from_address.address_space(), lambda s: s.get_reference(snap, from_address, to_address, operand_index))

    def get_references_from(self, snap, from_address) -> 'Collection[DBTraceReference]':
        return delegate_read(from_address.address_space(), lambda s: s.get_references_from(snap, from_address), [])

    def get_references_from_range(self, span, range):
        return delegate_read(range.address_space(), lambda s: s.get_references_from_range(span, range), [])

    def clear_references_from(self, span, range):
        delegate_delete_v(range.address_space(), lambda s: s.clear_references_from(span, range))

    def get_reference_sources(self, span) -> 'AddressSetView':
        return AddressSetView(union(*[s.get_reference_sources(span) for s in self.mem_spaces_view]))

    def get_reference_destinations(self, span) -> 'AddressSetView':
        return AddressSetView(union(*[s.get_reference_destinations(span) for s in self.mem_spaces_view]))

    def get_reference_count_from(self, snap, from_address):
        return delegate_read_i(from_address.address_space(), lambda s: s.get_reference_count_from(snap, from_address), 0)

    def get_reference_count_to(self, snap, to_address):
        return delegate_read_i(to_address.address_space(), lambda s: s.get_reference_count_to(snap, to_address), 0)

    def get_references_by_symbol_id(self, id) -> 'Collection[DBTraceReference]':
        return delegate_collection(self.all_spaces_view, lambda m: m.get_references_by_symbol_id(id))
