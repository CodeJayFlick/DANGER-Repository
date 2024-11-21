class DebugCOFFSymbolsHeader:
    def __init__(self):
        self.numberOfSymbols = 0
        self.lvaToFirstSymbol = 0
        self.numberOfLinenumbers = 0
        self.lvaToFirstLinenumber = 0
        self.rvaToFirstByteOfCode = 0
        self.rvaToLastByteOfCode = 0
        self.rvaToFirstByteOfData = 0
        self.rvaToLastByteOfData = 0

    @staticmethod
    def create_debug_coff_symbols_header(reader, debug_dir):
        debugCOFFSymbolsHeader = DebugCOFFSymbolsHeader()
        debugCOFFSymbolsHeader.init_debug_coff_symbols_header(reader, debug_dir)
        return debugCOFFSymbolsHeader

    def init_debug_coff_symbols_header(self, reader, debug_dir):
        ptr = debug_dir.get_pointer_to_raw_data()
        if not self.check_pointer(ptr):
            Msg.error(self, "Invalid pointer {}".format(hex(ptr)))
            return
        self.numberOfSymbols = reader.read_int(ptr)
        ptr += 4
        self.lvaToFirstSymbol = reader.read_int(ptr)
        ptr += 4
        self.numberOfLinenumbers = reader.read_int(ptr)
        ptr += 4
        self.lvaToFirstLinenumber = reader.read_int(ptr)
        ptr += 4
        self.rvaToFirstByteOfCode = reader.read_int(ptr)
        ptr += 4
        self.rvaToLastByteOfCode = reader.read_int(ptr)
        ptr += 4
        self.rvaToFirstByteOfData = reader.read_int(ptr)
        ptr += 4
        self.rvaToLastByteOfData = reader.read_int(ptr)

    def check_pointer(self, pointer):
        return True

    @property
    def symbol_table(self):
        if not hasattr(self, '_symbol_table'):
            self._symbol_table = DebugCOFFSymbolTable.create_debug_coff_symbol_table(reader=self.reader, debug_symbols_header=self)
        return self._symbol_table

    @property
    def line_numbers(self):
        if not hasattr(self, '_line_numbers'):
            if self.numberOfLinenumbers > 0 and self.numberOfLinenumbers < NTHeader.MAX_SANE_COUNT:
                self._line_numbers = [DebugCOFFLineNumber.create_debug_coff_line_number(reader=self.reader, ptr=ptr) for _ in range(self.numberOfLinenumbers)]
        return self._line_numbers

    def get_symbol_table(self):
        return self.symbol_table

    def get_line_numbers(self):
        return self.line_numbers

    def get_number_of_symbols(self):
        return self.numberOfSymbols

    def get_first_symbol_lva(self):
        return self.lvaToFirstSymbol

    def get_number_of_linenumbers(self):
        return self.numberOfLinenumbers

    def get_first_linenumber_lva(self):
        return self.lvaToFirstLinenumber

    def get_first_byte_of_code_rva(self):
        return self.rvaToFirstByteOfCode

    def get_last_byte_of_code_rva(self):
        return self.rvaToLastByteOfCode

    def get_first_byte_of_data_rva(self):
        return self.rvaToFirstByteOfData

    def get_last_byte_of_data_rva(self):
        return self.rvaToLastByteOfData
