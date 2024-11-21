Here is the translation of the Java code into Python:

```Python
class CompositeDataTypeImpl:
    def __init__(self, path=None, name="", universal_id=None, source_archive=None, last_change_time=0, last_change_time_in_source_archive=0):
        super().__init__(path or CategoryPath.ROOT, name, universal_id, source_archive, last_change_time, last_change_time_in_source_archive)
        self.description = ""

    def get_stored_packing_value(self):
        return self.packing

    def get_stored_minimum_alignment(self):
        return self.minimum_alignment

    def data_type_name_changed(self, dt, old_name):
        pass  # ignored

    @staticmethod
    def get_preferred_component_length(data_type, length):
        if DataTypeComponent.uses_zero_length_component(data_type):
            return 0
        if (self.is_packing_enabled() or isinstance(self, Union) and not isinstance(data_type, Dynamic)):
            length = -1  # force use of data type size
        dt_length = data_type.get_length()
        if length <= 0:
            length = dt_length
        elif dt_length > 0 and dt_length < length:
            length = dt_length
        if length <= 0:
            raise ValueError("Positive length must be specified for {} component".format(data_type.display_name))
        return length

    def has_language_dependent_length(self):
        pass  # abstract method, not implemented in this class

    @staticmethod
    def is_not_yet_defined():
        return self.num_components == 0 and not self.is_packing_enabled()

    def is_part_of(self, data_type):
        return DataTypeUtilities.is_second_part_of_first(self, data_type)

    def check_ancestry(self, dt):
        if self.equals(dt):
            raise ValueError("Data type {} can't contain itself.".format(self.display_name))
        elif DataTypeUtilities.is_second_part_of_first(dt, self):
            raise ValueError("{} has {} within it.".format(dt.display_name, self.display_name))

    @staticmethod
    def validate_data_type(data_type):
        if data_type == DataType.DEFAULT:
            if self.is_packing_enabled() or isinstance(self, Union):
                return Undefined1DataType.data_type
            return data_type
        elif isinstance(data_type, Dynamic):
            dynamic_dt = Dynamic(data_type)
            if not dynamic_dt.can_specify_length():
                raise ValueError("The {} data type is not allowed in a composite data type.".format(data_type.display_name))
        else:
            raise ValueError("The {} data type is not allowed in a composite data type.".format(data_type.display_name))

    def update_bit_field_data_type(self, bitfield_component, old_dt, new_dt):
        if not bitfield_component.is_bit_field_component():
            raise AssertionError("expected bit field component")
        bitfield_dt = BitFieldDataType(bitfield_component.data_type)
        if bitfield_dt.base_data_type != old_dt:
            return False
        if new_dt is not None:
            BitFieldDataType.check_base_data_type(new_dt)
            max_bit_size = 8 * new_dt.length()
            if bitfield_dt.bit_size > max_bit_size:
                raise InvalidDataTypeException("Replacement data type too small for bit field")
        try:
            new_bitfield_dt = BitFieldDataType(new_dt, bitfield_dt.declared_bit_size(), bitfield_dt.bit_offset())
            bitfield_component.data_type = new_bitfield_dt
            old_dt.remove_parent(self)
            new_dt.add_parent(self)
        except InvalidDataTypeException as e:
            raise AssertionError("unexpected") from e

    def set_description(self, desc):
        self.description = desc if desc is not None else ""

    def get_description(self):
        return self.description

    @staticmethod
    def get_value(buf, settings, length):
        return None  # abstract method, not implemented in this class

    def set_value(self, buf, settings, length, value):
        raise NotYetImplementedException("setValue() not implemented")

    def add(self, data_type):
        return self.add(data_type, -1, None, None)

    def add(self, data_type, length):
        return self.add(data_type, length, None, None)

    def add(self, data_type, field_name, comment):
        return self.add(data_type, -1, field_name, comment)

    def insert(self, ordinal, data_type, length=-1):
        return self.insert(ordinal, data_type, length, None, None)

    @staticmethod
    def get_mnemonic(settings):
        return self.display_name

    def set_name(self, name):
        if not self.check_valid_name(name):
            raise InvalidNameException("Invalid name: {}".format(name))
        self.name = name

    def repack(self, notify=True):
        pass  # abstract method, not implemented in this class

    @staticmethod
    def get_packing_type():
        if self.packing < DEFAULT_PACKING:
            return PackingType.DISABLED
        elif self.packing == DEFAULT_PACKING:
            return PackingType.DEFAULT
        else:
            return PackingType.EXPLICIT

    def set_to_default_packed(self):
        self.set_stored_packing_value(DEFAULT_PACKING)

    @staticmethod
    def get_explicit_packing_value():
        return self.packing

    def set_explicit_packing_value(self, packing_value):
        if packing_value <= 0:
            raise ValueError("explicit packing value must be positive: {}".format(packing_value))
        self.set_stored_packing_value(packing_value)

    @staticmethod
    def get_alignment_type():
        if self.minimum_alignment < DEFAULT_ALIGNMENT:
            return AlignmentType.MACHINE
        elif self.minimum_alignment == DEFAULT_ALIGNMENT:
            return AlignmentType.DEFAULT
        else:
            return AlignmentType.EXPLICIT

    def set_to_default_aligned(self):
        self.set_stored_minimum_alignment(DEFAULT_ALIGNMENT)

    @staticmethod
    def get_explicit_minimum_alignment():
        return self.minimum_alignment

    def set_explicit_minimum_alignment(self, minimum_alignment):
        if minimum_alignment <= 0:
            raise ValueError("explicit minimum alignment must be positive: {}".format(minimum_alignment))
        self.set_stored_minimum_alignment(minimum_alignment)

    @staticmethod
    def get_non_packed_alignment():
        alignment = None
        if self.minimum_alignment == DEFAULT_ALIGNMENT:
            alignment = 1
        elif self.minimum_alignment == MACHINE_ALIGNMENT:
            alignment = self.data_organization.machine_alignment()
        else:
            alignment = self.minimum_alignment
        return alignment

    abstract_method = "get_alignment"

    def __str__(self):
        return CompositeInternal.toString(self)
```

Please note that this is a direct translation of the Java code into Python, and it may not be perfect. Some methods or variables might need to be adjusted according to their usage in your specific context.