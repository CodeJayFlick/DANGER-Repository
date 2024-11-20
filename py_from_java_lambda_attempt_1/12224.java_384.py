Here is the translation of the Java code into Python:

```Python
class AlignedComponentPacker:
    def __init__(self, pack_value, data_organization):
        self.data_organization = data_organization
        self.bit_field_packing = data_organization.get_bit_field_packing()
        self.pack_value = pack_value

    def add_component(self, dtc, is_last_component=False):
        if dtc.get_data_type() == DataType.DEFAULT:
            raise ValueError("unsupported component")
        if not self.pack_component(dtc):
            self.init_group(dtc, is_last_component)
        self.last_component = dtc
        self.next_ordinal += 1

        self.default_alignment = get_lcm(self.default_alignment)

    def components_changed(self):
        return self.components_changed_

    def default_alignment_(self):
        return self.default_alignment

    def length_(self):
        if not self.last_component:
            return 0
        offset = 0
        if self.group_offset >= 0 and isinstance(self.last_component.get_data_type(), BitFieldDataType) \
                and self.bit_field_packing.use_ms_convention():
            last_bitfield_dt = (BitFieldDataType)(self.last_component.get_data_type())
            offset = self.group_offset + last_bitfield_dt.get_base_type_size()
        else:
            offset = self.last_component.get_offset() + self.last_component.get_length()
            if not self.bit_field_packing.use_ms_convention() and isinstance(self.last_component.get_data_type(), BitFieldDataType) \
                    and self.last_component.is_zero_bit_field():
                # factor in trailing zero-length bitfield
                size_alignment = last_bitfield_dt.get_base_data_type().get_alignment()
                get_bit_field_alignment(last_bitfield_dt)
                offset = DataOrganizationImpl.get_aligned_offset(size_alignment, offset)

        return offset

    def get_bit_field_type_size(self, dtc):
        component_dt = dtc.get_data_type()
        if isinstance(component_dt, BitFieldDataType:
            return (BitFieldDataType)(component_dt).get_base_type_size()

    def get_bit_field_alignment(self, bitfield_dt):
        if not self.bit_field_packing.use_ms_convention() and self.pack_value != CompositeInternal.DEFAULT_PACKING:
            # GCC always uses 1 when packing regardless of pack value
            return 1

        return CompositeAlignmentHelper.get_packed_alignment(bitfield_dt.get_base_data_type().get_alignment(), self.pack_value)

    def is_ignored_zero_bit_field(self, zero_bitfield_dt):
        if not zero_bitfield_dt.is_zero_length():
            return False
        if self.bit_field_packing.use_ms_convention():
            # TODO: verify when :0 is first component
            return self.last_component and isinstance(self.last_component.get_data_type(), BitFieldDataType)

    def get_zero_bit_field_alignment(self, zero_bitfield_dt, is_last_component):
        if self.is_ignored_zero_bit_field(zero_bitfield_dt):
            return -1

        if not self.bit_field_packing.is_type_alignment_enabled():
            zero_length_bit_field_boundary = self.bit_field_packing.get_zero_length_boundary()
            if zero_length_bit_field_boundary > 0:
                return zero_length_bit_field_boundary
            return 1

        pack = self.pack_value
        if not self.bit_field_packing.use_ms_convention() and not is_last_component:
            # GCC ignores pack value for :0 bitfield alignment but considers it when passing alignment along to structure
            pack = CompositeInternal.NO_PACKING

        return CompositeAlignmentHelper.get_packed_alignment(zero_bitfield_dt.get_base_data_type().get_alignment(), pack)

    def init_group(self, dtc, is_last_component):
        self.group_offset = self.length()
        self.last_alignment = 1

        if isinstance(dtc.get_data_type(), BitFieldDataType):
            zero_bit_field_dt = (BitFieldDataType)(dtc.get_data_type())

            if dtc.is_zero_bit_field():
                # An alignment of -1 indicates field is ignored
                alignment = get_zero_bit_field_alignment(zero_bitfield_dt, is_last_component)

                zero_bit_offset = 7 if self.data_organization.is_big_endian() else 0
                if zero_bit_field_dt.get_bit_offset() != zero_bit_offset or \
                        zero_bit_field_dt.get_storage_size() != 1:
                    try:
                        packed_bit_field_dt = BitFieldDataType(zero_bitfield_dt.get_base_data_type(), 0, zero_bit_offset)
                        dtc.set_data_type(packed_bit_field_dt)
                    except InvalidDataTypeException as e:
                        raise AssertException("unexpected", e)

                    self.components_changed_ = True

                if is_last_component:
                    # special handling of zero-length bitfield when it is last component
                    offset = DataOrganizationImpl.get_aligned_offset(zero_bitfield_dt.get_base_data_type().get_alignment(), self.group_offset)
                    update_component(dtc, self.next_ordinal - 1, offset, 0, alignment > 0 and alignment or 1)

                else:
                    # Avoid conveying zero alignment onto structure
                    # Next component can influence alignment
                    zero_alignment = alignment

                    if not self.bit_field_packing.use_ms_convention():
                        last_alignment = alignment

            else:
                self.last_component = None  # first in allocation group
                align_and_pack_bitfield(dtc)  # relies on self.group_offset when self.last_component==null

        elif dtc.is_zero_bit_field():
            if not is_last_component and self.bit_field_packing.use_ms_convention():
                return False  # start new group for non-bitfield

    def adjust_zero_length_bit_field(self, ordinal, minimum_alignment):
        min_offset = DataOrganizationImpl.get_aligned_offset(minimum_alignment, self.group_offset)
        zero_alignment_offset = DataOrganizationImpl.get_aligned_offset(zero_alignment, self.group_offset)

        if min_offset >= zero_alignment_offset:
            # natural offset satisfies :0 alignment
            self.group_offset = min_offset

        else:
            self.group_offset = zero_alignment_offset

        update_component(self.last_component, ordinal - 1, self.group_offset, 0, minimum_alignment)
    ...

def get_lcm(all_components_lcm):
    if last_alignment == 0:
        return last_alignment
    # factor in pack value, which may have been ignored when aligning component
    alignment = last_alignment
    if pack_value > 0 and alignment > pack_value:
        alignment = pack_value

    return DataOrganizationImpl.get_least_common_multiple(all_components_lcm, alignment)

def update_component(dtc, ordinal, offset, length, alignment):
    if ordinal != dtc.ordinal or offset != dtc.offset or length != dtc.length:
        dtc.update(ordinal, offset, length)
        self.components_changed_ = True

    last_alignment = max(last_alignment, alignment)

...

class BitFieldDataType(DataType):
    def __init__(self, base_data_type, declared_bit_size, bit_offset=0):
        super().__init__()
        self.base_data_type = base_data_type
        self.declared_bit_size = declared_bit_size
        self.bit_offset = bit_offset

    @property
    def get_base_type_size(self):
        return self.base_data_type.get_alignment()

...

class DataOrganization:
    ...

def align_and_pack_non_bitfield_component(dtc, min_offset):
    component_dt = dtc.get_data_type()
    if isinstance(component_dt, BitFieldDataType) and component_dt.is_zero_length():
        # assume lastComponent bit- field has already been packed and has correct bit-offset
        offset = group_offset
        bits_consumed = 0

...

def align_and_pack_bitfield(dtc):
    bit_field_dt = (BitFieldDataType)(dtc.get_data_type())
    if self.last_component and isinstance(self.last_component.get_data_type(), BitFieldDataType):
        last_bitfield_dt = (BitFieldDataType)(self.last_component.get_data_type())

        offset = group_offset
        bits_consumed = 0

...

def set_bit_field_dtype(dtc, bit_field_dt, bits_consumed):
    byte_size = (bit_field_dt.bit_size + bits_consumed + 7) // 8
    bit_offset; ...

...
```

Please note that this is a direct translation of the Java code into Python. The original code has many comments and notes which are not included in this translation as they may be specific to the context or environment where the code was written.