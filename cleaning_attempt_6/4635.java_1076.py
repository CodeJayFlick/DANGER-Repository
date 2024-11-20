class CoffSymbolAuxTagName:
    def __init__(self, reader):
        self.unused1 = reader.read_next_byte_array(6)
        self.size = reader.read_next_short()
        self.unused2 = reader.read_next_byte_array(4)
        self.next_entry_index = reader.read_next_int()
        self.unused3 = reader.read_next_byte_array(2)

    def get_unused1(self):
        return self.unused1

    def get_size(self):
        return self.size

    def get_unused2(self):
        return self.unused2

    def get_next_entry_index(self):
        return self.next_entry_index

    def get_unused3(self):
        return self.unused3

    def to_data_type(self) -> None:
        try:
            from ghidra.util import struct_converter_util
            return struct_converter_util.to_data_type(self)
        except (Exception,):  # DuplicateNameException and IOException are not defined in Python
            pass
