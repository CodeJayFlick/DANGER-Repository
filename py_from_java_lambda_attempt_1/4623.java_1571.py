Here is the translation of the given Java code into Python:

```Python
import struct

class CoffSymbol:
    def __init__(self):
        self.e_name = None
        self.e_value = 0
        self.e_scnum = 0
        self.e_type = 0
        self.e_sclass = 0
        self.e_numaux = 0
        self._auxiliary_symbols = []

    def read(self, reader):
        if reader.peek_next_int() == 0:
            name_index = reader.read_next_int()
            string_table_index = (reader.get_file_header().get_symbol_table_pointer() + 
                                  (reader.get_file_header().get_symbol_table_entries() * CoffConstants.SYMBOL_SIZEOF))
            self.e_name = reader.read_ascii_string(string_table_index + name_index)
        else:
            self.e_name = reader.read_next_ascii_string(CoffConstants.SYMBOL_NAME_LENGTH)

        self.e_value = reader.read_next_int()
        self.e_scnum = reader.read_next_short()
        self.e_type = reader.read_next_short()
        self.e_sclass = reader.read_next_byte()
        self.e_numaux = reader.read_next_byte()

        for _ in range(self.e_numaux):
            self._auxiliary_symbols.append(CoffSymbolAuxFactory().read(reader, self))

    def get_name(self):
        return self.e_name

    def get_value(self):
        return self.e_value & 0xffffffffL

    def move(self, offset):
        self.e_value += offset

    def get_section_number(self):
        return self.e_scnum

    def get_basic_type(self):
        return self.e_type & 0xf

    def get_derived_type(self, derived_index):
        if not (1 <= derived_index <= 6):
            raise RuntimeError("1 <= derivedIndex <= 6")
        derived_type = (self.e_type & 0xffff) >> 4
        if derived_index > 1:
            derived_type >>= (derived_index * 2)
        return derived_type & 3

    def get_storage_class(self):
        return self.e_sclass

    def get_auxiliary_count(self):
        return self.e_numaux

    def get_auxiliary_symbols(self):
        return list(self._auxiliary_symbols)

    def to_data_type(self):
        struct = struct.StructConverterUtil.parse_name(type(self))
        data_type = struct.add(struct.ASCII, "e_name", None)
        data_type.add(int, "e_value", None)
        data_type.add(short, "e_scnum", None)
        data_type.add(short, "e_type", None)
        data_type.add(byte, "e_sclass", None)
        return data_type

    def is_section(self):
        if self.e_type == CoffSymbolType.T_NULL:
            if self.e_value == 0 and self.e_sclass == CoffSymbolStorageClass.C_STAT:
                for aux in self._auxiliary_symbols:
                    if isinstance(aux, CoffSymbolAuxSection):
                        return True
        return False

    def __str__(self):
        buffer = StringBuffer()
        buffer.append(self.get_name())
        buffer.append('  ')
        buffer.append(f"Value=0x{self.get_value():X}")
        buffer.append('  ')
        buffer.append(str(self.e_scnum))
        buffer.append('  ')
        buffer.append(str(self.e_type))
        buffer.append('  ')
        buffer.append(str(self.e_sclass))
        return buffer.toString()
```

Please note that Python does not have direct equivalent of Java's `struct` and `DuplicateNameException`. Also, Python has its own way to handle exceptions.