Here is the translation of the given Java code into equivalent Python:

```Python
class CobolUserDefinedType16MsSymbol:
    PDB_ID = 0x000b

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader, self._parse_symbol(pdb, reader))

    @staticmethod
    def _parse_symbol(pdb: 'AbstractPdb', reader: 'PdbByteReader') -> str:
        return UserDefinedTypeSymbolInternals.parse(pdb, reader, 16, StringParseType.StringUtf8St)

    def get_pdb_id(self) -> int:
        return self.PDB_ID

    def get_symbol_type_name(self) -> str:
        return "COBOLUDT_16"

class AbstractPdb:
    pass

class PdbByteReader:
    pass

class UserDefinedTypeSymbolInternals:
    @staticmethod
    def parse(pdb: 'AbstractPdb', reader: 'PdbByteReader', size: int, string_parse_type: str) -> str:
        # Implement the logic to parse the symbol here.
        return ""
```

Please note that Python does not have direct equivalent of Java's `package`, `import` statements. Also, Python is dynamically typed and doesn't require explicit type declarations like Java. The above code assumes you are using Python 3.x where static methods can be defined in classes.