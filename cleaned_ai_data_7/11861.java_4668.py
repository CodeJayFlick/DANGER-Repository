class CompositeDB:
    def __init__(self):
        pass

    @property
    def composite_adapter(self):
        return self._composite_adapter

    @composite_adapter.setter
    def composite_adapter(self, value):
        self._composite_adapter = value

    @property
    def component_adapter(self):
        return self._component_adapter

    @component_adapter.setter
    def component_adapter(self, value):
        self._component_adapter = value

    def __init__(self, data_mgr, cache, composite_adapter, component_adapter, record):
        super().__init__()
        self.composite_adapter = composite_adapter
        self.component_adapter = component_adapter
        self.record = record
        self.initialize()

    def initialize(self):
        pass  # abstract method

    @staticmethod
    def get_preferred_component_length(data_type, length):
        if DataTypeComponent.uses_zero_length_component(data_type):
            return 0
        if (is_packing_enabled() or isinstance(self, Union) and not isinstance(data_type, Dynamic)):
            length = -1  # force use of data type size
        dt_length = data_type.get_length()
        if length <= 0:
            length = dt_length
        elif dt_length > 0 and dt_length < length:
            length = dt_length
        if length <= 0:
            raise ValueError("Positive length must be specified for " + str(data_type) + " component")
        return length

    def get_name(self):
        return self.record.get_string(CompositeDBAdapter.COMPOSITE_NAME_COL)

    @staticmethod
    def do_get_category_id():
        pass  # abstract method

    def update_bit_field_data_type(self, bitfield_component, old_dt, new_dt):
        if not isinstance(bitfield_component, BitFieldComponent):
            raise AssertionError("expected bit field component")
        bitfield_dt = (BitFieldDBDataType)bitfield_component.get_data_type()
        if bitfield_dt.get_base_data_type() != old_dt:
            return False
        if new_dt is not None:
            BitFieldDataType.check_base_data_type(new_dt)
            max_bit_size = 8 * new_dt.get_length()
            if bitfield_dt.get_bit_size() > max_bit_size:
                raise InvalidDataException("Replacement data type too small for bit field")
        try:
            bitfield_dt = BitFieldDBDataType(new_dt, bitfield_dt.get_declared_bit_size(), bitfield_dt.get_bit_offset())
            bitfield_component.set_data_type(bitfield_dt)
            old_dt.remove_parent(self)
            new_dt.add_parent(self)
        except InvalidDataException as e:
            raise AssertionError("unexpected") from e

    def refresh(self):
        try:
            rec = self.composite_adapter.get_record(key)
            if rec is not None:
                self.record = rec
                self.initialize()
                return super().refresh()
        except IOException as e:
            data_mgr.db_error(e)

    @staticmethod
    def do_set_description(desc):
        pass  # abstract method

    def get_mnemonic(self, settings):
        return self.get_display_name()

    @staticmethod
    def do_set_category_path_record(category_id):
        pass  # abstract method

    def is_part_of(self, data_type_interest):
        lock.acquire()
        try:
            check_is_valid()
            return DataTypeUtilities.is_second_part_of_first(self, data_type_interest)
        finally:
            lock.release()

    @staticmethod
    def do_check_ancestry(data_type):
        pass  # abstract method

    def get_universal_id(self):
        return UniversalID(self.record.get_long_value(CompositeDBAdapter.COMPOSITE_UNIVERSAL_DT_ID))

    def set_universal_id(self, id):
        lock.acquire()
        try:
            check_is_deleted()
            self.record.set_long_value(CompositeDBAdapter.COMPOSITE_UNIVERSAL_DT_ID, id.value)
            self.composite_adapter.update_record(self.record, False)
            data_mgr.data_type_changed(self, False)
        finally:
            lock.release()

    @staticmethod
    def do_get_source_archive_id():
        pass  # abstract method

    def set_source_archive_id(self, id):
        lock.acquire()
        try:
            check_is_deleted()
            self.record.set_long_value(CompositeDBAdapter.COMPOSITE_SOURCE_ARCHIVE_ID_COL, id.value)
            self.composite_adapter.update_record(self.record, True)
            if not repack(False, True):
                data_mgr.data_type_changed(self, False)
        finally:
            lock.release()

    @staticmethod
    def get_non_packed_alignment():
        alignment = DEFAULT_ALIGNMENT
        minimum_alignment = get_stored_minimum_alignment()
        if minimum_alignment == MACHINE_ALIGNMENT:
            return machine_alignment
        elif minimum_alignment == DEFAULT_ALIGNMENT:
            return 1
        else:
            return minimum_alignment

    def repack(self, is_auto_change, notify):
        pass  # abstract method

    @staticmethod
    def get_stored_packing_value():
        lock.acquire()
        try:
            check_is_valid()
            return self.record.get_int_value(CompositeDBAdapter.COMPOSITE_PACKING_COL)
        finally:
            lock.release()

    @staticmethod
    def set_explicit_minimum_alignment(minimum_alignment):
        if minimum_alignment <= 0:
            raise ValueError("explicit minimum alignment must be positive: " + str(minimum_alignment))
        set_stored_minimum_alignment(minimum_alignment)

    @staticmethod
    def get_defined_components():
        pass  # abstract method

    def post_pointer_resolve(self, definition_dt, handler):
        composite = (Composite)definition_dt
        defined_components = composite.get_defined_components()
        my_defined_components = self.get_defined_components()
        if len(defined_components) != len(my_defined_components):
            raise ValueError("mismatched definition data type")
        for i in range(len(defined_components)):
            dtc = defined_components[i]
            dt = dtc.get_data_type()
            if isinstance(dt, Pointer):
                my_dtc = my_defined_components[i]
                my_dtc.set_data_type(data_mgr.resolve(dt, handler))
                dt.add_parent(self)

    def set_packing_enabled(self, enabled):
        if enabled == self.is_packing_enabled():
            return
        self.record.set_int_value(CompositeDBAdapter.COMPOSITE_MIN_ALIGN_COL,
                                   DEFAULT_ALIGNMENT)
        self.composite_adapter.update_record(self.record, True)

    @staticmethod
    def fixup_components():
        pass  # abstract method

class UniversalID:
    def __init__(self, value):
        self.value = value

    def get_value(self):
        return self.value

# Other classes and methods are not included here as they were part of the original Java code.
