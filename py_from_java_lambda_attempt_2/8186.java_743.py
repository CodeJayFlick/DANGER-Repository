Here is the translation of the given Java code into equivalent Python:

```Python
class GlobalProcedureStartMipsMsSymbol:
    PDB_ID = 0x1115

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader, ProcedureStartMipsSymbolInternals.parse(pdb, reader))

    def get_pdb_id(self) -> int:
        return self.PDB_ID

    def get_symbol_type_name(self) -> str:
        return "GPROCMIPSSYM"


class AbstractPdb:
    pass


class PdbByteReader:
    pass


class ProcedureStartMipsSymbolInternals:
    @staticmethod
    def parse(pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        # implementation of parsing logic here
        return None

```

Please note that Python does not have direct equivalent to Java's package declaration, so I did not include any package declarations in the above code. Also, some methods like `parse` are just placeholders and would need actual implementation based on your requirements.