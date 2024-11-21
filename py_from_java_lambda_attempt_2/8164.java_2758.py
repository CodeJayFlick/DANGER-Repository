Here is the translation of the given Java code into Python:

```Python
class FrameSecurityCookieMsSymbol:
    PDB_ID = 0x113a
    
    class CookieType(enum.Enum):
        INVALID = ("invalid", -1)
        COPY = ("COPY", 0)
        XOR_SP = ("XOR_SP", 1)
        XOR_BP = ("XOR_BP", 2)
        XOR_R13 = ("XOR_R13", 3)

        BY_VALUE = {value: value_name for value_name, _ in CookieType.__members__.values()}

    def __init__(self):
        self.offset = None
        self.register_index = None
        self.register_name = None
        self.cookie_type = None
        self.flags = None

    @classmethod
    def from_value(cls, val):
        return cls.BY_VALUE.get(val, FrameSecurityCookieMsSymbol.CookieType.INVALID)

    def __str__(self):
        return str(self.offset) + " " + str(self.register_name) + " " + str(self.cookie_type) + " " + hex(self.flags)

    @classmethod
    def from_pdb_reader(cls, pdb, reader):
        symbol = super().__init__()
        symbol.offset = reader.parse_var_sized_offset(32)
        symbol.register_index = reader.parse_unsigned_short_val()
        symbol.register_name = RegisterName(pdb, symbol.register_index)
        symbol.cookie_type = FrameSecurityCookieMsSymbol.CookieType.from_value(reader.parse_unsigned_byte_val())
        symbol.flags = reader.parse_unsigned_byte_val()
        return symbol

    def get_pdb_id(self):
        return self.PDB_ID

    @property
    def offset(self):
        return self._offset

    @offset.setter
    def offset(self, value):
        self._offset = value

    @property
    def register_index(self):
        return self._register_index

    @register_index.setter
    def register_index(self, value):
        self._register_index = value

    @property
    def register_name(self):
        return self._register_name

    @register_name.setter
    def register_name(self, value):
        self._register_name = value

    @property
    def cookie_type(self):
        return self._cookie_type

    @cookie_type.setter
    def cookie_type(self, value):
        self._cookie_type = value

    @property
    def flags(self):
        return self._flags

    @flags.setter
    def flags(self, value):
        self._flags = value

    def emit(self, builder):
        builder.append(f"{self.get_symbol_type_name()}: {str(self.register_name)}+{hex(self.offset)}, Type: {str(self.cookie_type)}, {hex(self.flags)}")

    def get_symbol_type_name(self):
        return "FRAMECOOKIE"

class RegisterName:
    def __init__(self, pdb, register_index):
        self.pdb = pdb
        self.register_index = register_index

    def __str__(self):
        return f"{self.pdb.get_register_name_string()}{self.register_index}"

class PdbByteReader:
    def parse_var_sized_offset(self, size):
        pass  # implement this method

    def parse_unsigned_short_val(self):
        pass  # implement this method

    def parse_unsigned_byte_val(self):
        pass  # implement this method
```

Note that I have not implemented the `PdbByteReader` class as it was not provided in the original Java code. You would need to provide your own implementation of these methods based on how you are reading the PDB file.