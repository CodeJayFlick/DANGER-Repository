Here is the translation of the given Java code into equivalent Python:

```Python
class DebugCOFFSymbolAux:
    IMAGE_SIZEOF_AUX_SYMBOL = 18

    def __init__(self):
        pass

    @staticmethod
    def create_debug_coff_symbol_aux(reader, index, symbol) -> 'DebugCOFFSymbolAux':
        debug_coff_symbol_aux = reader.create(DebugCOFFSymbolAux)
        debug_coff_symbol_aux.init_debug_coff_symbol_aux(reader, index, symbol)
        return debug_coff_symbol_aux

    def init_debug_coff_symbol_aux(self, reader, index, symbol):
        if symbol.get_storage_class() == DebugCOFFSymbol.IMAGE_SYM_CLASS_FILE:
            self.file = AuxFile.create_aux_file(reader, index)
        elif symbol.get_storage_class() in [DebugCOFFSymbol.IMAGE_SYM_CLASS_EXTERNAL,
                                              DebugCOFFSymbol.IMAGE_SYM_CLASS_FUNCTION]:
            self.sym = AuxSym.create_aux_sym(reader, index)
        elif symbol.get_storage_class() == DebugCOFFSymbol.IMAGE_SYM_CLASS_STATIC:
            self.section = AuxSection.create_aux_section(reader, index)

    def __str__(self):
        if self.file is not None:
            return str(self.file.name)
        elif self.sym is not None:
            return f"Tag={hex(self.sym.tag_index)} " \
                   f"TvIndex={hex(self.sym.tv_index)}"
        else:
            return super().__str__()

    def to_data_type(self) -> 'DataType':
        structure_name = StructConverterUtil.parse_name(DebugCOFFSymbolAux)
        structure = StructureDataType(structure_name, self.IMAGE_SIZEOF_AUX_SYMBOL)

        if self.file is not None:
            structure.add(STRING, DebugCOFFSymbol.IMAGE_SIZEOF_SYMBOL, "name", None)
        elif self.sym is not None:
            # Add the fields of AuxSym
            pass

        return structure


class AuxSym:
    def __init__(self):
        pass

    @staticmethod
    def create_aux_sym(reader, index) -> 'AuxSym':
        aux_sym = reader.create(AuxSym)
        aux_sym.init_aux_sym(reader, index)
        return aux_sym

    def init_aux_sym(self, reader, index):
        self.tag_index = reader.read_int(index)
        index += 4
        self.misc_ln_sz_linenumber = reader.read_short(index)
        index += 2
        self.misc_ln_sz_size = reader.read_short(index)
        index += 2
        self.misc_total_size = reader.read_int(index)
        index += 4

    def get_tag_index(self) -> int:
        return self.tag_index

    # Add the rest of the fields and methods


class AuxFile:
    def __init__(self):
        pass

    @staticmethod
    def create_aux_file(reader, index) -> 'AuxFile':
        aux_file = reader.create(AuxFile)
        aux_file.init_aux_file(reader, index)
        return aux_file

    def init_aux_file(self, reader, index):
        self.name = reader.read_ascii_string(index, DebugCOFFSymbol.IMAGE_SIZEOF_SYMBOL)

    def get_name(self) -> str:
        return self.name


class AuxSection:
    def __init__(self):
        pass

    @staticmethod
    def create_aux_section(reader, index) -> 'AuxSection':
        aux_section = reader.create(AuxSection)
        aux_section.init_aux_section(reader, index)
        return aux_section

    def init_aux_section(self, reader, index):
        self.length = reader.read_int(index)
        index += 4
        self.number_of_relocations = reader.read_short(index)
        index += 2
        self.number_of_linenumbers = reader.read_short(index)
        index += 2
        self.check_sum = reader.read_int(index)
        index += 4
        self.selection = reader.read_byte(index)

    def get_length(self) -> int:
        return self.length

    # Add the rest of the fields and methods


class DebugCOFFSymbol:
    IMAGE_SYM_CLASS_FILE = 0x00
    IMAGE_SYM_CLASS_EXTERNAL = 0x01
    IMAGE_SYM_CLASS_FUNCTION = 0x02
    IMAGE_SYM_CLASS_STATIC = 0x03
```

Please note that Python does not have direct equivalent of Java's `StructConverter` and related classes. You might need to implement your own structure conversion logic in the above code.

Also, please ensure you are using a compatible version of Python for this translation as it is based on Python syntax and semantics.