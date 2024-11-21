Here is the equivalent Python code:

```Python
class EnregisteredSymbolRelativeDARMsSymbol:
    PDB_ID = 0x1145

    def __init__(self, pdb, reader):
        super().__init__(pdb, reader)
        self.base_register = reader.read_uint16()
        self.base_register_name = RegisterName(pdb, self.base_register)
        fields = reader.read_uint16()
        self.is_spilled_user_defined_type_member = (fields & 0x0001) == 0x0001
        fields >>= 4  # Skipping 3 padding bits too.
        self.offset_in_parent = fields & 0x0fff
        self.offset_to_base_register = reader.read_int()  # signed
        self.parse_range_and_gaps(reader)

    def get_pdb_id(self):
        return self.PDB_ID

    def get_symbol_type_name(self):
        return "DEFRANGE_REGISTER_REL"

    def emit(self, builder):
        builder.append(self.get_symbol_type_name())
        builder.format(": [%s + %04X]", self.base_register_name.toString(), self.offset_to_base_register)
        if self.is_spilled_user_defined_type_member:
            builder.format(" spilledUserDefinedTypeMember offset at %d", self.offset_in_parent)
        self.emit_range_and_gaps(builder)


class RegisterName:
    def __init__(self, pdb, base_register):
        pass

    def toString(self):
        return ""
```

Note that I did not implement the `AbstractPdb`, `PdbByteReader`, and `RegisterName` classes as they are not provided in your code. Also, some methods like `parse_range_and_gaps(reader)` and `emit_range_and_gaps(builder)` seem to be missing their implementation.