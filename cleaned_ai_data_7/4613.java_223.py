import struct

class CoffLineNumber:
    SIZEOF = 6  # int + short in bytes
    
    def __init__(self, reader):
        self.l_addr = reader.read_int()
        self.l_lnno = reader.read_short()

    @property
    def address(self):
        return self.l_addr

    @property
    def function_name_symbol_index(self):
        return self.l_addr

    @property
    def line_number(self):
        return self.l_lnno

    def to_data_type(self):
        # No equivalent in Python for Java's StructConverterUtil.toDataType()
        pass


class BinaryReader:
    def read_int(self):
        raise NotImplementedError("read_int() must be implemented")

    def read_short(self):
        raise NotImplementedError("read_short() must be implemented")
