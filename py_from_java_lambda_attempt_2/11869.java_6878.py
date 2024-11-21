Here's your Java code translated into Python:

```Python
class DataTypeComponentDB:
    def __init__(self, data_mgr, parent, ordinal, offset):
        self.data_mgr = data_mgr
        self.parent = parent
        self.ordinal = ordinal
        self.offset = offset
        self.length = 1
        self.record = None

    @property
    def cached_data_type(self):
        return self._cached_data_type

    @cached_data_type.setter
    def cached_data_type(self, value):
        if not isinstance(value, type) or issubclass(value, DataType):
            raise ValueError("Invalid data type")
        self._cached_data_type = value

    def __init__(self, data_mgr, parent, ordinal, offset, datatype, length):
        this(data_mgr, parent, ordinal, offset)
        self.cached_data_type = datatype
        self.length = length

    @property
    def is_bit_field_component(self):
        if not hasattr(self, 'record'):
            return False
        id = self.record.get_long_value(ComponentDBAdapter.COMPONENT_DT_ID_COL)
        return data_mgr.get_table_id(id) == DataTypeManagerDB.BITFIELD

    @property
    def is_zero_bit_field_component(self):
        if self.is_bit_field_component:
            bit_field = BitFieldDataType(self.cached_data_type)
            return bit_field.get_bit_size() == 0
        return False

    def get_key(self):
        if not hasattr(self, 'record'):
            return -1
        return self.record.get_key()

    @property
    def data_type(self):
        if not hasattr(self, '_cached_data_type') or self._cached_data_type is None:
            if not hasattr(self, 'record'):
                return DataType.DEFAULT
            id = self.record.get_long_value(ComponentDBAdapter.COMPONENT_DT_ID_COL)
            if id == -1:
                return DataType.DEFAULT
            return data_mgr.get_data_type(id)
        return self._cached_data_type

    @property
    def parent(self):
        return self._parent

    @parent.setter
    def parent(self, value):
        if not isinstance(value, CompositeDB):
            raise ValueError("Invalid parent")
        self._parent = value

    @property
    def offset(self):
        return self._offset

    @offset.setter
    def offset(self, value):
        self._offset = value

    @property
    def length(self):
        return self._length

    @length.setter
    def length(self, value):
        if not isinstance(value, int) or value < 0:
            raise ValueError("Invalid length")
        self._length = value

    def contains_offset(self, off):
        if off == self.offset:  # separate check required to handle zero-length case
            return True
        return off > self.offset and off < (self.offset + self.length)

    @property
    def ordinal(self):
        return self._ordinal

    @ordinal.setter
    def ordinal(self, value):
        if not isinstance(value, int) or value < 0:
            raise ValueError("Invalid ordinal")
        self._ordinal = value

    @property
    def end_offset(self):
        if self.length == 0:  # separate check required to handle zero-length case
            return self.offset
        return self.offset + self.length - 1

    def get_comment(self):
        if not hasattr(self, 'record'):
            return None
        return self.record.get_string(ComponentDBAdapter.COMPONENT_COMMENT_COL)

    @property
    def default_settings(self):
        if not hasattr(self, '_default_settings') or self._default_settings is None:
            if not hasattr(self, 'record'):
                return get_data_type().get_default_settings()
            else:
                self._default_settings = SettingsDBManager(data_mgr, this, record.get_key())
        return self._default_settings

    def set_default_settings(self, settings):
        if not hasattr(self, 'record') or self.record is None:
            if not isinstance(settings, Settings):
                raise ValueError("Invalid default settings")
            else:
                get_data_type().set_default_settings(settings)
        else:
            if _default_settings is None:
                _default_settings = new SettingsDBManager(data_mgr, this, record.get_key())
            _default_settings.update(settings)

    def set_comment(self, comment):
        try:
            if not hasattr(self, 'record'):
                return
            self.record.set_string(ComponentDBAdapter.COMPONENT_COMMENT_COL, comment)
            adapter.update_record(record)
            data_mgr.data_type_changed(parent, False)
        except IOException as e:
            data_mgr.db_error(e)

    @property
    def field_name(self):
        if is_zero_bit_field_component():
            return ""
        if not hasattr(self, 'record'):
            return None
        return self.record.get_string(ComponentDBAdapter.COMPONENT_FIELD_NAME_COL)

    def set_field_name(self, name):
        try:
            if not isinstance(name, str) or len(name.strip()) == 0:
                raise ValueError("Invalid field name")
            check_duplicate_name(name)
            if not hasattr(self, 'record'):
                return
            self.record.set_string(ComponentDBAdapter.COMPONENT_FIELD_NAME_COL, name)
            adapter.update_record(record)
            data_mgr.data_type_changed(parent, False)
        except IOException as e:
            data_mgr.db_error(e)

    def __eq__(self, other):
        if not isinstance(other, DataTypeComponent):
            return False
        my_dt = self.get_data_type()
        other_dt = other.get_data_type()

        if offset != other.offset or length != other.length or ordinal != other.ordinal or \
           !system_utilities.is_equal(get_field_name(), other.get_field_name()) or \
           !system_utilities.is_equal(get_comment(), other.get_comment()):
            return False

        if isinstance(my_dt, Pointer) and not my_dt.path_name().equals(other_dt.path_name()):
            return False
        elif isinstance(my_dt, Structure):
            return isinstance(other_dt, Structure)
        elif isinstance(my_dt, Union):
            return isinstance(other_dt, Union)
        elif isinstance(my_dt, Array):
            return isinstance(other_dt, Array)
        elif isinstance(my_dt, Pointer):
            return isinstance(other_dt, Pointer)
        else:
            return my_dt.__class__ == other_dt.__class__

    def __hash__(self):
        # It is not expected that these objects ever be put in a hash map
        return super().__hash__()

    @property
    def is_equivalent(self):
        if self.get_data_type() is None or other.get_data_type() is None:
            return False

        my_parent = parent
        aligned = (my_parent.__class__ == CompositeDB) and my_parent.is_packing_enabled()
        # Components don't need to have matching offset when they are aligned
        if not aligned and self.offset != other.offset or \
           !system_utilities.is_equal(get_field_name(), other.get_field_name()) or \
           !system_utilities.is_equal(get_comment(), other.get_comment()):
            return False

        # Component lengths need only be checked for dynamic types
        if length != other.length and isinstance(my_dt, Dynamic):
            return False

        return system_utilities.is_same_or_equivalent_data_type(self.get_data_type(), other.get_data_type())

    def update(self, new_ordinal, new_offset, new_length):
        if self.length < 0:
            raise ValueError("Cannot set data type component length to " + str(new_length) + ".")
        ordinal = new_ordinal
        offset = new_offset
        length = new_length

        if not hasattr(self, 'record'):
            return
        record.set_int_value(ComponentDBAdapter.COMPONENT_ORDINAL_COL, ordinal)
        record.set_int_value(ComponentDBAdapter.COMPONENT_OFFSET_COL, offset)
        record.set_int_value(ComponentDBAdapter.COMPONENT_SIZE_COL, length)

    def set_offset(self, new_offset):
        self.offset = new_offset

    def set_ordinal(self, new_ordinal):
        self.ordinal = new_ordinal
        if not hasattr(self, 'record'):
            return
        record.set_int_value(ComponentDBAdapter.COMPONENT_ORDINAL_COL, ordinal)
        update_record()

    def set_length(self, length):
        self.length = length

    @property
    def get_record(self):
        return self._get_record

    @set_record.setter
    def _record(self, value):
        if not isinstance(value, DBRecord):
            raise ValueError("Invalid record")
        self._record = value

    def is_undefined(self):
        return hasattr(self, 'record') and self.record is None and cached_data_type is None