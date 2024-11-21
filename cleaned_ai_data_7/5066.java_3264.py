class DebugCOFFLineNumber:
    IMAGE_SIZEOF_LINENUMBER = 6

    def __init__(self):
        self.symbol_table_index = None
        self.virtual_address = None
        self.line_number = None

    @classmethod
    def create_debug_coff_line_number(cls, reader, index):
        debug_coff_line_number = cls()
        debug_coff_line_number.init_debug_coff_line_number(reader, index)
        return debug_coff_line_number

    def init_debug_coff_line_number(self, reader, index):
        self.symbol_table_index = reader.read_int(index)
        self.virtual_address = reader.read_int(index)
        index += 4
        self.line_number = reader.read_short(index)

    @property
    def symbol_table_index(self):
        return self._symbol_table_index

    @symbol_table_index.setter
    def symbol_table_index(self, value):
        self._symbol_table_index = value

    @property
    def virtual_address(self):
        return self._virtual_address

    @virtual_address.setter
    def virtual_address(self, value):
        self._virtual_address = value

    @property
    def line_number(self):
        return self._line_number

    @line_number.setter
    def line_number(self, value):
        self._line_number = value


class BinaryReader:
    SIZEOF_INT = 4

    def read_int(self, index):
        # TO DO: implement this method
        pass

    def read_short(self, index):
        # TO DO: implement this method
        pass
