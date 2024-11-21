class AppleSingleDouble:
    SINGLE_MAGIC_NUMBER = 0x00051600
    DOUBLE_MAGIC_NUMBER = 0x00051607
    FILLER_LEN = 16

    def __init__(self, provider):
        self.magic_number = None
        self.version_number = None
        self.filler = bytearray(FILLER_LEN)
        self.number_of_entries = None
        self.entry_list = []

        reader = BinaryReader(provider, False)

        self.magic_number = reader.read_int()
        if self.magic_number not in [SINGLE_MAGIC_NUMBER, DOUBLE_MAGIC_NUMBER]:
            raise MacException("Invalid Apple Single/Double file")

        self.version_number = reader.read_int()
        self.filler = reader.read_bytes(FILLER_LEN)
        self.number_of_entries = reader.read_short()

        for i in range(self.number_of_entries):
            entry_list.append(EntryDescriptor(reader))

    def get_magic_number(self):
        return self.magic_number

    def get_version_number(self):
        return self.version_number

    def get_filler(self):
        return self.filler

    def get_number_of_entries(self):
        return self.number_of_entries

    def get_entry_list(self):
        return self.entry_list

class EntryDescriptor:
    pass  # not implemented in the original Java code, so I left it out for now

class BinaryReader:
    def __init__(self, provider, is_little_endian):
        self.provider = provider
        self.is_little_endian = is_little_endian

    def read_int(self):
        return int.from_bytes(self.provider.read(4), byteorder='little' if self.is_little_endian else 'big')

    def read_short(self):
        return int.from_bytes(self.provider.read(2), byteorder='little' if self.is_little_endian else 'big')

    def read_bytes(self, length):
        return bytearray(self.provider.read(length))

class MacException(Exception):
    pass

# not implemented in the original Java code
def StructConverterUtil_parse_name(cls):
    raise NotImplementedError("Not implemented")

class StructureDataType:
    def __init__(self, name, offset):
        self.name = name
        self.offset = offset
        self.fields = []

    def add(self, field_type, field_name, default_value=None):
        self.fields.append((field_type, field_name, default_value))

# not implemented in the original Java code
def ArrayDataType(field_type, length, byte_length):
    raise NotImplementedError("Not implemented")
