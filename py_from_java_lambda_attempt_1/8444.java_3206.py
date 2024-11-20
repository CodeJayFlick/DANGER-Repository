Here is the translation of the given Java code into equivalent Python:

```Python
class ManagedStMsType:
    PDB_ID = 0x140f

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader, "StringUtf8St")

    def get_pdb_id(self) -> int:
        return self.PDB_ID
```

Note that Python does not have direct equivalent of Java's package and import statements. Also, the `@Override` annotation is used in Java to indicate that a method overrides one from its superclass; however, this concept doesn't exist directly in Python as it uses inheritance instead.

The type hints (`'AbstractPdb'`, `'PdbByteReader'`) are not necessary for runtime and can be removed if you're using an older version of Python.