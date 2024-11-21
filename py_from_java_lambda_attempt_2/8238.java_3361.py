Here is the translation of the given Java code into equivalent Python:

```Python
class LocalThreadStorage32StMsSymbol:
    PDB_ID = 0x100e

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader, ThreadStorageSymbolInternals.parse_32_st(reader, pdb))

    @property
    def pdb_id(self) -> int:
        return self.PDB_ID

    def get_symbol_type_name(self) -> str:
        return "LTHREAD32_ST"
```

Note that Python does not have direct equivalent of Java's `public`, `private` and other access modifiers. The concept is similar but implemented differently in Python.

In the above code, I used a type hint for the parameters in the constructor (`__init__`) method to indicate their types. This is not enforced at runtime but can be useful during static analysis or when using tools that support type hints.