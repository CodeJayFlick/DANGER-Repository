Here is the translation of the given Java code into Python:

```Python
class DebugCOFFSymbolTable:
    def __init__(self):
        self.ptr_to_symbol_table = None
        self.symbol_count = 0
        self.symbols = []

    @classmethod
    def create_debug_coff_symbol_table(cls, reader, coff_header, offset):
        debug_coff_symbol_table = cls()
        debug_coff_symbol_table.init_debug_coff_symbol_table(reader, coff_header, offset)
        return debug_coff_symbol_table

    def init_debug_coff_symbol_table(self, reader, coff_header, offset):
        self.ptr_to_symbol_table = coff_header.get_first_symbol_lva() + offset
        self.symbol_count = coff_header.get_number_of_symbols()

# TODO: 
# should symbol table info in NT Header agree with info in COFF Header?

        if 0 < self.symbol_count < 65536:
            for i in range(self.symbol_count):
                symbols.append(DebugCOFFSymbol.create_debug_coff_symbol(reader, self.ptr_to_symbol_table + (i * DebugCOFFSymbol.IMAGE_SIZEOF_SYMBOL), self))

    def get_string_table_index(self):
        return self.ptr_to_symbol_table + (self.symbol_count * DebugCOFFSymbol.IMAGE_SIZEOF_SYMBOL)

    @property
    def symbols(self):
        return self._symbols

    @symbols.setter
    def symbols(self, value):
        self._symbols = value


class DebugCOFFSymbolsHeader:
    pass


class NTHeader:
    MAX_SANE_COUNT = 65536


class DebugCOFFSymbol:
    IMAGE_SIZEOF_SYMBOL = None

    @classmethod
    def create_debug_coff_symbol(cls, reader, offset, symbol_table):
        return cls()
```

Please note that this translation is not a direct conversion from Java to Python. The original code seems to be part of the Ghidra reverse engineering tool and uses custom classes like `FactoryBundledWithBinaryReader`, which are not available in standard Python libraries.