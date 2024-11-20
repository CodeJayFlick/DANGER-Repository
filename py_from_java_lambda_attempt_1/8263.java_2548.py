Here is the translation of the Java code to Python:
```
class ObjectNameMsSymbol:
    PDB_ID = 0x1101

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader, "StringUtf8Nt")

    def get_pdb_id(self) -> int:
        return self.PDB_ID

    def get_symbol_type_name(self) -> str:
        return "OBJNAME"
```
Note that I've used Python 3.6+ syntax and features to translate the code. Specifically:

* The `class` keyword is used to define a class.
* The `__init__` method is equivalent to the Java constructor, with the same signature (taking two arguments).
* The `super()` function is used to call the parent class's constructor.
* The `-> None` syntax indicates that the `__init__` method returns no value.
* The `get_pdb_id` and `get_symbol_type_name` methods are equivalent to their Java counterparts, with similar signatures.

I've also removed some of the Java-specific comments and documentation, as they don't have a direct equivalent in Python.