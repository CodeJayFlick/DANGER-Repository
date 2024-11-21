Here is the translation of the given Java code into equivalent Python:

```Python
class LocalProcedure32IdMsSymbol:
    PDB_ID = 0x1146

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader, ProcedureStartSymbolInternals.parse_32(pdb, reader))

    def get_pdb_id(self) -> int:
        return self.PDB_ID

    def get_symbol_type_name(self) -> str:
        return "LPROC32_ID"

    def get_special_type_string(self) -> str:
        return "ID"


class AbstractPdb:
    pass


class PdbByteReader:
    pass


class ProcedureStartSymbolInternals:
    @staticmethod
    def parse_32(pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        # implement this method as needed
        return None

```

Please note that Python does not have direct equivalent of Java's static imports, so I've left the `import` statements out. Also, in Python, we don't need to specify types for variables or function parameters like we do in Java. The `@Override` annotation is also not needed as it serves no purpose in Python.