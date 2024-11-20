class AbstractPointerMsType:
    def __init__(self):
        pass

    class PointerType(enum.Enum):
        INVALID = ("invalid", -1)
        NEAR = ("near", 0)  # 16- bit pointer
        FAR = ("far", 1)  # 16:16 far pointer
        HUGE = ("huge", 2)  # 16:16 huge pointer
        SEGMENT_BASED = ("base(seg)", 3)
        VALUE_BASED = ("base(val)", 4)
        SEGMENT_VALUE_BASED = ("base(segval)", 5)
        ADDRESS_BASED = ("base(addr)", 6)
        SEGMENT_ADDRESS_BASED = ("base(segaddr)", 7)
        TYPE_BASED = ("base(type)", 8)
        SELF_BASED = ("base(adr)", 9)  # 16:32 pointer
        NEAR32 = ("", 10)  # 32- bit pointer
        FAR32 = ("far32", 11)  # 16:32 pointer
        PTR64 = ("far64", 12)  # 64-bit pointer
        UNSPECIFIED = ("unspecified", 13)

    class PointerMode(enum.Enum):
        INVALID = ("", -1)
        POINTER = ("*", 0)  # Normal
        LVALUE_REFERENCE = ("&", 1)  # Same as older style reference
        MEMBER_DATA_POINTER = ("::*", 2)
        MEMBER_FUNCTION_POINTER = ("::*", 3)
        RVALUE_REFERENCE = ("&&", 4)

    class MemberPointerType(enum.Enum):
        INVALID = ("invalid", -1)
        UNSPECIFIED = ("pdm16_nonvirt", 0)  # 16- bit pointer
        DATA_SINGLE_INHERITANCE = ("pdm16_vfcn", 1)  # 16:16 far pointer
        DATA_MULTIPLE_INHERITANCE = ("pdm16_vbase", 2)  # 16:16 huge pointer
        DATA_VIRTUAL_INHERITANCE = ("pdm32_nvvfcn", 3)
        DATA_GENERAL = ("pdm32_vbase", 4)
        FUNCTION_SINGLE_INHERITANCE = ("pmf16_nearvsa", 5)
        FUNCTION_MULTIPLE_INHERITANCE = ("pmf16_nearvma", 6)
        FUNCTION_VIRTUAL_INHERITANCE = ("pmf16_narnvbase", 7)
        FUNCTION_SINGLE_INHERITANCE_1632 = ("pmf16_farvsa", 8)
        FUNCTION_MULTIPLE_INHERITANCE_1632 = ("pmf16_farnvma", 9)
        FUNCTION_VIRTUAL_INHERITANCE_1632 = ("pmf16_farnvbase", 10)
        FUNCTION_SINGLE_INHERITANCE_32 = ("pmf32_nvsa", 11)
        FUNCTION_MULTIPLE_INHERITANCE_32 = ("pmf32_nvma", 12)
        FUNCTION_VIRTUAL_INHERITANCE_32 = ("pmf32_nvbase", 13)

    def __init__(self, pdb, reader):
        super().__init__()
        self.pdb = pdb
        self.reader = reader

    def parse_extended_pointer_info(self, int_size, string_type) -> None:
        if self.pointer_mode in [AbstractPointerMsType.PointerMode.MEMBER_DATA_POINTER,
                                  AbstractPointerMsType.PointerMode.MEMBER_FUNCTION_POINTER]:
            member_pointer_containing_class_record_number = RecordNumber.parse(pdb=self.pdb, reader=self.reader)
            member_pointer_type = MemberPointerType.from_value(self.reader.read_unsigned_short())
            if self.reader.has_more():
                # TODO: I think there might be possible padding
                self.reader.read_bytes_remaining()
        elif self.pointer_type == AbstractPointerMsType.PointerType.SEGMENT_BASED:
            base_segment = pdb.parse_segment(reader=self.reader)
            if self.reader.has_more():
                # TODO: I think there might be possible padding
                self.reader.read_bytes_remaining()
        elif self.pointer_type == AbstractPointerMsType.PointerType.TYPE_BASED:
            pointer_base_type_record_number = RecordNumber.parse(pdb=pdb, reader=reader, record_category='TYPE', int_size=int_size)
            name = reader.read_string(string_type=string_type)
            if self.reader.has_more():
                # TODO: I think there might be possible padding
                self.reader.skip_padding()
        elif self.pointer_type == AbstractPointerMsType.PointerType.INVALID:
            base_symbol = reader.read_string(string_type=string_type)
            if self.reader.has_more():
                # TODO: more investigation--enable code during research.
                PdbLog.message(f"Unexpected data in {self.__class__.__name__}: \n{reader.dump()}")
        else:
            if self.reader.has_more():
                # TODO: more investigation--enable code during research
                PdbLog.message(f"Unexpected data in {self.__class__.__name__}: \n{reader.dump()}")

    def get_underlying_type(self) -> 'AbstractMsType':
        return self.pdb.get_type_record(underlying_record_number=self.underlying_record_number)

    def get_underlying_record_number(self) -> RecordNumber:
        return self.underlying_record_number

    @property
    def size(self):
        if hasattr(self, '_size'):
            return self._size
        else:
            raise AttributeError("Size is not set")

    @size.setter
    def size(self, value: int):
        self._size = BigInteger(value)

    def emit(self, builder: str, bind: Bind) -> None:
        my_builder = StringBuilder()
        if self.is_flat:
            my_builder.append('flat ')
        switch (self.pointer_mode):
            case AbstractPointerMsType.PointerMode.MEMBER_DATA_POINTER | \
                 AbstractPointerMsType.PointerMode.MEMBER_FUNCTION_POINTER:
                pdb.get_type_record(member_pointer_containing_class_record_number).emit(builder=builder, bind=Bind.NONE)
                my_builder.append(self.pointer_mode)
                my_builder.append(' <')
                my_builder.append(member_pointer_type)
                my_builder.append('> ')
            case AbstractPointerMsType.PointerMode.POINTER | \
                 AbstractPointerMsType.PointerMode.LVALUE_REFERENCE | \
                 AbstractPointerMsType.PointerMode.RVALUE_REFERENCE:
                if self.is_const:
                    my_builder.append('const ')
                if self.is_volatile:
                    my_builder.append('volatile ')
                break
        builder.insert(0, my_builder)
        builder.append('  ')
        get_underlying_type().emit(builder=builder, bind=Bind.PTR)

    def parse_attributes(self) -> None:
        pass

    @property
    def pointer_type(self):
        return self._pointer_type

    @pointer_type.setter
    def pointer_type(self, value: PointerType):
        self._pointer_type = value

    @property
    def is_flat(self):
        return self._is_flat

    @is_flat.setter
    def is_flat(self, value: bool):
        self._is_flat = value

    @property
    def is_volatile(self):
        return self._is_volatile

    @is_volatile.setter
    def is_volatile(self, value: bool):
        self._is_volatile = value

    @property
    def is_const(self):
        return self._is_const

    @is_const.setter
    def is_const(self, value: bool):
        self._is_const = value

    @property
    def member_pointer_type(self):
        return self._member_pointer_type

    @member_pointer_type.setter
    def member_pointer_type(self, value: MemberPointerType):
        self._member_pointer_type = value

    abstract def get_my_size(self) -> int:
