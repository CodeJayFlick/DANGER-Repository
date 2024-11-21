Here is the translation of the given Java code into equivalent Python:

```Python
class RegisterRelativeAddress32StMsSymbol:
    PDB_ID = 0x100d

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader)
        self.offset = reader.parse_var_sized_offset(32)
        self.type_record_number = RecordNumber.parse(pdb, reader, RecordCategory.TYPE, 32)
        self.register_index = reader.parse_unsigned_short_val()
        self.name = reader.parse_string(pdb, StringParseType.STRING_UTF8_ST)
        reader.align4()
        self.register_name = RegisterName(pdb, self.register_index)

    def get_pdb_id(self) -> int:
        return self.PDB_ID

    def get_symbol_type_name(self) -> str:
        return "REGREL32_ST"
```

Note that Python does not have direct equivalent of Java's `public`, `private` and other access modifiers. The code is written in a way to follow the same logic as the original Java code, but without using these keywords.

Also note that some parts like exception handling (`throws PdbException`) are removed because Python doesn't support checked exceptions.