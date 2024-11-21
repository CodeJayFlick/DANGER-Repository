Here is the translation of the given Java code into equivalent Python:

```Python
class GlobalThreadStorage32MsSymbol:
    PDB_ID = 0x1113

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader, ThreadStorageSymbolInternals.parse_32(reader, pdb))

    @property
    def pdb_id(self) -> int:
        return self.PDB_ID

    def get_symbol_type_name(self) -> str:
        return "GTHREAD32"
```

Note that Python does not have direct equivalent of Java's package declaration. Also, Python is dynamically typed and doesn't require explicit type declarations for variables or function parameters like Java does.

In the `__init__` method, I used Python's built-in support for inheritance with the `super()` function to call the parent class constructor. The `@property` decorator in front of the `pdb_id` property is a way to implement getter-only properties in Python (there are no setter methods).