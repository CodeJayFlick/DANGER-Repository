class ReferenceSymbolInternals:
    def __init__(self, pdb):
        super().__init__(pdb)

    @property
    def sum_name(self):
        return self._sum_name

    @sum_name.setter
    def sum_name(self, value):
        self._sum_name = value

    @property
    def offset_actual_symbol_in_dollar_dollar_symbols(self):
        return self._offset_actual_symbol_in_dollar_dollar_symbols

    @offset_actual_symbol_in_dollar_dollar_symbols.setter
    def offset_actual_symbol_in_dollar_dollar_symbols(self, value):
        self._offset_actual_symbol_in_dollar_dollar_symbols = value

    @property
    def module_index(self):
        return self._module_index

    @module_index.setter
    def module_index(self, value):
        self._module_index = value

    def parse_st(self, pdb, reader):
        result = ReferenceSymbolInternalsSt(pdb)
        result.sum_name = reader.parse_unsigned_int_val()
        result.offset_actual_symbol_in_dollar_dollar_symbols = reader.parse_unsigned_int_val()
        result.module_index = reader.parse_unsigned_short_val()
        reader.align4()
        return result

    def parse2(self, pdb, reader):
        result = ReferenceSymbolInternals2(pdb)
        result.sum_name = reader.parse_unsigned_int_val()
        result.offset_actual_symbol_in_dollar_dollar_symbols = reader.parse_unsigned_int_val()
        result.module_index = reader.parse_unsigned_short_val()
        result.name = reader.parse_string(pdb, "StringUtf8Nt")
        reader.align4()
        return result

    def emit(self, builder):
        builder.append(f": {self.sum_name:08X}: ({self.module_index}, {self.offset_actual_symbol_in_dollar_dollar_symbols})")


class ReferenceSymbolInternalsSt(ReferenceSymbolInternals):
    pass


class ReferenceSymbolInternals2(ReferenceSymbolInternals):
    def __init__(self, pdb):
        super().__init__(pdb)

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, value):
        self._name = value

    def emit(self, builder):
        super().emit(builder)
        builder.append(" ")
        builder.append(self.name)


class PdbByteReader:
    def parse_unsigned_int_val(self):
        # implementation of parsing unsigned int val
        pass

    def parse_unsigned_short_val(self):
        # implementation of parsing unsigned short val
        pass

    def align4(self):
        # implementation of alignment 4 bytes
        pass

    def parse_string(self, pdb, string_type):
        # implementation of parsing a string
        pass


class AbstractPdb:
    pass
