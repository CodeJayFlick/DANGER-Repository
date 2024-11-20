class ElfSymbolTable:
    def __init__(self):
        pass

    @staticmethod
    def create_elf_symbol_table(reader, header, symbol_table_section, file_offset, addr_offset,
                                 length, entry_size, string_table, is_dynamic) -> 'ElfSymbolTable':
        elf_symbol_table = ElfSymbolTable()
        elf_symbol_table.init_elf_symbol_table(reader, header, symbol_table_section, file_offset,
                                                 addr_offset, length, entry_size, string_table, is_dynamic)
        return elf_symbol_table

    def init_elf_symbol_table(self, reader, header, symbol_table_section, file_offset, addr_offset,
                               length, entry_size, string_table, is_dynamic):
        self.symbol_table_section = symbol_table_section
        self.file_offset = file_offset
        self.addr_offset = addr_offset
        self.length = length
        self.entry_size = entry_size
        self.string_table = string_table
        self.is32bit = header.get_is_32_bit()
        self.is_dynamic = is_dynamic

        ptr = reader.get_pointer_index()
        reader.set_pointer_index(file_offset)

        symbol_count = int(length / entry_size)
        symbols = []

        for i in range(symbol_count):
            reader.set_pointer_index(ptr + (i * entry_size))
            sym = ElfSymbol.create_elf_symbol(reader, i, self, header)
            symbols.append(sym)

        sorted_symbols = sorted(symbols, key=lambda x: x.get_name())
        for symbol in sorted_symbols:
            symbol.init_symbol_name(reader, string_table)

        reader.set_pointer_index(ptr)

    def is_dynamic(self):
        return self.is_dynamic

    def get_string_table(self):
        return self.string_table

    def get_symbol_count(self):
        return len(symbols)

    def get_symbols(self):
        return symbols

    def get_symbol_index(self, symbol):
        for i in range(len(symbols)):
            if symbols[i] == symbol:
                return i
        return -1

    def get_symbol_at(self, addr):
        for symbol in self.symbols:
            if symbol.get_value() == addr:
                return symbol
        return None

    def get_global_symbols(self):
        global_symbols = []
        for symbol in self.symbols:
            if symbol.get_bind() == ElfSymbol.STB_GLOBAL:
                global_symbols.append(symbol)
        return global_symbols

    def get_source_files(self):
        source_files = []
        for symbol in self.symbols:
            if symbol.get_type() == ElfSymbol.STT_FILE:
                name = symbol.get_name_as_string()
                if name is not None:
                    source_files.append(name)
        return source_files

    def add_symbol(self, symbol):
        symbols.extend([symbol])

    @staticmethod
    def to_bytes(dc):
        bytes = []
        for i in range(len(symbols)):
            symbytes = symbols[i].to_bytes(dc)

            if i == 0:
                bytes = [0] * len(symbytes) * len(symbols)
            System.arraycopy(symbytes, 0, bytes, i * len(symbytes), len(symbytes))
        return bytes

    def get_length(self):
        return self.length

    def get_address_offset(self):
        return self.addr_offset

    def get_table_section_header(self):
        return self.symbol_table_section

    def get_file_offset(self):
        return self.file_offset

    def get_entry_size(self):
        return int(self.entry_size)
