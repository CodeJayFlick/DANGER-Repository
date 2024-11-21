class ReferenceListEntry:
    def __init__(self, reader, map):
        self.id = reader.read_short()
        self.name_offset = reader.read_short()
        self.attributes = reader.read_byte()
        self.data_offset = read_3byte_value(reader)
        self.handle = reader.read_int()

        self._name = map.get_string_at(name_offset)

    def read_3byte_value(self, reader):
        value1 = reader.read_byte() & 0xFF
        value2 = reader.read_byte() & 0xFF
        value3 = reader.read_byte() & 0xFF

        if reader.is_little_endian():
            return (value3 << 16) | (value2 << 8) | value1
        else:
            return (value1 << 16) | (value2 << 8) | value3

    def get_id(self):
        return self.id

    def get_name(self):
        return self._name

    def get_name_offset(self):
        return self.name_offset

    def get_attributes(self):
        return self.attributes

    def get_data_offset(self):
        return self.data_offset

    def get_handle(self):
        return self.handle


def to_data_type(self) -> dict:
    name = "ReferenceListEntry"
    struct = {"id": WORD, "nameOffset": WORD, "attributes": BYTE,
              "dataOffset": UnsignedInteger3DataType(), "handle": DWORD}
    return struct
