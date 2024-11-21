class CoffSectionHeader:
    def __init__(self):
        pass

    def __init__(self, reader, header):
        self._header = header
        self.read_name(reader)

        self.s_paddr = reader.read_int()
        self.s_vaddr = reader.read_int()
        self.s_size = reader.read_int()
        self.s_scnptr = reader.read_int()
        self.s_relptr = reader.read_int()
        self.s_lnnoptr = reader.read_int()
        self.s_nreloc = reader.read_short() & 0xffff
        self.s_nlnno = reader.read_short() & 0xffff
        self.s_flags = reader.read_int()
        self.s_reserved = 0
        self.s_page = 0

    def read_name(self, reader):
        name_bytes = reader.read_next_byte_array(CoffConstants.SECTION_NAME_LENGTH)
        if (name_bytes[0] == 0 and name_bytes[1] == 0 and name_bytes[2] == 0 and name_bytes[3] == 0):  # if first 4 bytes are zero, then lookup name in string table
            data_converter = reader.is_little_endian() and LittleEndianDataConverter.INSTANCE or BigEndianDataConverter.INSTANCE
            name_index = data_converter.get_int(name_bytes, 4)  # string table index
            string_table_index = self._header.get_symbol_table_pointer() + (self._header.get_symbol_table_entries() * CoffConstants.SYMBOL_SIZEOF)
            self.s_name = reader.read_ascii_string(string_table_index + name_index)
        else:
            self.s_name = ''.join(map(chr, name_bytes)).strip()

    def get_name(self):
        return self.s_name

    def get_physical_address(self):
        return self.s_paddr

    def move(self, offset):
        self.s_paddr += offset

    def get_virtual_address(self):
        return self.s_vaddr

    def is_explicitly_byte_aligned(self):
        return (self.s_reserved & CoffSectionHeaderReserved.EXPLICITLY_BYTE_ALIGNED) != 0

    def get_size(self, language):
        if self.is_explicitly_byte_aligned():
            return self.s_size
        addressable_unit_size = language.get_address_factory().get_default_address_space().get_addressable_unit_size()
        return self.s_size * addressable_unit_size

    def get_pointer_to_raw_data(self):
        return self.s_scnptr

    def get_pointer_to_relocations(self):
        return self.s_relptr

    def get_pointer_to_line_numbers(self):
        return self.s_lnnoptr

    def get_relocation_count(self):
        return self.s_nreloc

    def get_line_number_count(self):
        return self.s_nlnno

    def get_flags(self):
        return self.s_flags

    def get_reserved(self):
        return self.s_reserved

    def get_page(self):
        return self.s_page

    def get_raw_data_stream(self, provider, language) -> bytes:
        addressable_unit_size = language.get_address_factory().get_default_address_space().get_addressable_unit_size()
        if (addressable_unit_size > 1 and language.is_big_endian()):
            return BigEndianUnitSizeByteSwapperInputStream(provider.get_input_stream(self.s_scnptr), addressable_unit_size)
        return provider.get_input_stream(self.s_scnptr)

    def is_processed_bytes(self, language):
        addressable_unit_size = language.get_address_factory().get_default_address_space().get_addressable_unit_size()
        return addressable_unit_size > 1 and language.is_big_endian()

    def parse(self, reader, header, monitor) -> None:
        orig_index = reader.get_pointer_index()
        try:
            self.parse_relocations(reader, header, monitor)
            self.parse_line_numbers(reader, monitor)
        finally:
            reader.set_pointer_index(orig_index)

    def parse_line_numbers(self, reader, monitor):
        reader.set_pointer_index(self.s_lnnoptr)
        for i in range(self.s_nlnno):
            if (monitor.is_cancelled()):
                break
            self._line_numbers.append(CoffLineNumber(reader))

    def parse_relocations(self, reader, header, monitor) -> None:
        reader.set_pointer_index(self.s_relptr)
        for i in range(self.s_nreloc):
            if (monitor.is_cancelled()):
                break
            self._relocations.append(CoffRelocation(reader, header))

    @staticmethod
    def to_data_type() -> DataType:
        struct = StructureDataType("CoffSectionHeader", 0)
        struct.add(ArrayDataType(ASCII, CoffConstants.SECTION_NAME_LENGTH), "s_name", None)
        struct.add(DWORD, "s_paddr", None)
        struct.add(DWORD, "s_vaddr", None)
        struct.add(DWORD, "s_size", None)
        struct.add(DWORD, "s_scnptr", None)
        struct.add(DWORD, "s_relptr", None)
        struct.add(DWORD, "s_lnnoptr", None)
        struct.add(WORD, "s_nreloc", None)
        struct.add(WORD, "s_nlnno", None)
        if (self._header.get_magic() == CoffMachineType.TICOFF1MAGIC):
            struct.add(BYTE, "s_reserved", None)
            struct.add(BYTE, "s_page", None)
        elif (self._header.get_magic() == CoffMachineType.TICOFF2MAGIC):
            struct.add(WORD, "s_reserved", None)
            struct.add(WORD, "s_page", None)

    def is_uninitialized_data(self) -> bool:
        return self.s_flags & CoffSectionHeaderFlags.STYP_BSS != 0 or self.s_scnptr == 0

    def is_initialized_data(self) -> bool:
        return (self.s_flags & CoffSectionHeaderFlags.STYP_DATA) != 0 and (self.s_flags & CoffSectionHeaderFlags.STYP_TEXT) == 0

    def is_data(self) -> bool:
        return self.is_initialized_data() or self.is_uninitialized_data()

    def is_readable(self) -> bool:
        return True

    def is_group(self) -> bool:
        return self.s_flags & CoffSectionHeaderFlags.STYP_GROUP != 0

    def is_writable(self) -> bool:
        return (self.s_flags & CoffSectionHeaderFlags.STYP_TEXT) == 0

    def is_executable(self) -> bool:
        return (self.s_flags & CoffSectionHeaderFlags.STYP_TEXT) != 0

    @staticmethod
    def get_offset_unit_size(language, section):
        if (section is None or not section.is_explicitly_byte_aligned()):
            addressable_unit_size = language.get_address_factory().get_default_address_space().get_addressable_unit_size()
            return addressable_unit_size
        else:
            return 1

    @staticmethod
    def get_address(language, offset, section):
        if (section is None or not section.is_explicitly_byte_aligned()):
            space = language.get_address_factory().get_default_data_space() if section is None or section.is_data() else language.get_address_factory().get_default_space()
            return space.get_address(offset * CoffSectionHeader.get_offset_unit_size(language, section))
        else:
            return Address(section.s_paddr + offset)

    @staticmethod
    def get_address2(language, offset, address_space):
        return address_space.get_address(offset * CoffSectionHeader.get_offset_unit_size(None, None))

class CoffRelocation:
    pass

class CoffLineNumber:
    pass

CoffConstants = {
    "SECTION_NAME_LENGTH": 8,
    "SYMBOL_SIZEOF": 4
}

LittleEndianDataConverter = object()
BigEndianDataConverter = object()

ASCII = object()

DWORD = object()
WORD = object()
BYTE = object()

StructConverterUtil = object()

DataType = object()

CoffMachineType = {
    "TICOFF1MAGIC": 0x10b,
    "TICOFF2MAGIC": 0x20b
}

CoffSectionHeaderReserved = {
    "EXPLICITLY_BYTE_ALIGNED": 0x0004
}

CoffSectionHeaderFlags = {
    "STYP_BSS": 0x10000,
    "STYP_DATA": 0x20000,
    "STYP_TEXT": 0x40000,
    "STYP_GROUP": 0x80000
}
