Here is the translation of the given Java code into equivalent Python:

```Python
class ManagedLocalOrParameterSIRMsSymbol:
    PDB_ID = 0x111f

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader)

    @property
    def pdb_id(self) -> int:
        return self.PDB_ID

    def get_symbol_type_name(self) -> str:
        return "MANREGISTER"


class AbstractLocalOrParameterStoredInRegisterMsSymbol:
    pass


class PdbByteReader:
    pass


class AbstractPdb:
    pass
```

Please note that Python does not have direct equivalent of Java's package, import statements or annotations. Also, the type hints are used to indicate the expected types of function parameters and return values.