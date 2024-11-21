Here is the translation of the given Java code into equivalent Python:

```Python
class LocalSymbolInOptimizedCodeMsSymbol:
    PDB_ID = 0x113e

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader)

    @property
    def pdb_id(self) -> int:
        return self.PDB_ID

    @property
    def symbol_type_name(self) -> str:
        return "LOCAL"

class AbstractLocalSymbolInOptimizedCodeMsSymbol:
    pass

class PdbByteReader:
    pass

class AbstractPdb:
    pass
```

Please note that Python does not have direct equivalent of Java's `package`, `public` and `throws`. Also, the concept of abstract classes is different in both languages. In this translation, I've used Python's built-in support for inheritance to mimic the behavior of abstract classes.