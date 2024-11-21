class RefListFlagsV0:
    SOURCE_LOBIT = 1 << 0
    IS_PRIMARY = 1 << 1
    IS_OFFSET = 1 << 2
    HAS_SYMBOL_ID = 1 << 3
    IS_SHIFT = 1 << 4
    SOURCE_HIBIT = 1 << 5

    def __init__(self, flags):
        self.flags = flags

    def __init__(self, is_primary=False, is_offset_ref=False, has_symbol_id=False,
                 is_shift_ref=False, source_type=None):
        self.flags = 0
        if source_type in [SourceType.USER_DEFINED, SourceType.IMPORTED]:
            self.flags |= RefListFlagsV0.SOURCE_LOBIT
        elif source_type == SourceType.ANALYSIS:
            self.flags |= RefListFlagsV0.SOURCE_HIBIT
        if is_primary:
            self.flags |= RefListFlagsV0.IS_PRIMARY
        if is_offset_ref:
            self.flags |= RefListFlagsV0.IS_OFFSET
        if has_symbol_id:
            self.flags |= RefListFlagsV0.HAS_SYMBOL_ID
        if is_shift_ref:
            self.flags |= RefListFlagsV0.IS_SHIFT

    def get_value(self):
        return self.flags & 0xFF

    @property
    def source_type(self):
        is_lo_bit = (self.flags & RefListFlagsV0.SOURCE_LOBIT) != 0
        is_hi_bit = (self.flags & RefListFlagsV0.SOURCE_HIBIT) != 0
        if is_hi_bit:
            return SourceType.IMPORTED if is_lo_bit else SourceType.ANALYSIS
        return SourceType.USER_DEFINED if is_lo_bit else SourceType.DEFAULT

    @property
    def has_symbol_id(self):
        return (self.flags & RefListFlagsV0.HAS_SYMBOL_ID) != 0

    @property
    def is_shift_ref(self):
        return (self.flags & RefListFlagsV0.IS_SHIFT) != 0

    @property
    def is_offset_ref(self):
        return (self.flags & RefListFlagsV0.IS_OFFSET) != 0

    @property
    def is_primary(self):
        return (self.flags & RefListFlagsV0.IS_PRIMARY) != 0

    def set_primary(self, is_primary=False):
        self.flags &= ~RefListFlagsV0.IS_PRIMARY
        if is_primary:
            self.flags |= RefListFlagsV0.IS_PRIMARY

    def set_has_symbol_id(self, has_symbol_id=False):
        self.flags &= ~RefListFlagsV0.HAS_SYMBOL_ID
        if has_symbol_id:
            self.flags |= RefListFlagsV0.HAS_SYMBOL_ID


class SourceType:
    USER_DEFINED = 1
    IMPORTED = 2
    ANALYSIS = 3
    DEFAULT = 4

SourceType = SourceType()
