Here is the translation of the given Java code into equivalent Python:

```Python
class UserDefinedType16MsSymbol:
    PDB_ID = 0x0004

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader, self._parse_symbol(pdb, reader))

    @staticmethod
    def _parse_symbol(pdb: 'AbstractPdb', reader: 'PdbByteReader') -> str:
        return UserDefinedTypeSymbolInternals.parse(pdb, reader, 16, StringParseType.StringUtf8St)

    def get_pdb_id(self) -> int:
        return self.PDB_ID

    def get_symbol_type_name(self) -> str:
        return "UDT_16"
```

Note that Python does not have direct equivalent of Java's `public`, `private` and other access modifiers. In Python, everything is public by default unless you explicitly use double underscore (`__`) to make it private.

Also note that the translation assumes there are classes or functions named `AbstractPdb`, `PdbByteReader`, `UserDefinedTypeSymbolInternals`, and `StringParseType.StringUtf8St` in your program.