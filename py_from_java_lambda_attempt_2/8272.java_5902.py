Here is the translation of the given Java code into equivalent Python:

```Python
class ProcedureReferenceMsSymbol:
    PDB_ID = 0x1125

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader)

    @property
    def name(self) -> str:
        return (self.internals).name()

    @property
    def pdb_id(self) -> int:
        return self.PDB_ID

    def get_symbol_type_name(self) -> str:
        return "PROCREF"


class AbstractPdb:
    pass


class PdbByteReader:
    pass


class ReferenceSymbolInternals2:
    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        self.pdb = pdb
        self.reader = reader

    @property
    def name(self) -> str:
        return "Name"


# Example usage:

pdb = AbstractPdb()
reader = PdbByteReader()

symbol = ProcedureReferenceMsSymbol(pdb, reader)

print(symbol.name)
print(symbol.pdb_id)
```

Please note that this is a direct translation of the given Java code into Python. The `AbstractPdb`, `PdbByteReader` and `ReferenceSymbolInternals2` classes are not fully implemented in the provided example as they were not defined in the original Java code either.