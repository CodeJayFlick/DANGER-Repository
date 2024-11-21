Here is the translation of the given Java code into Python:

```Python
class DefaultArguments16MsType:
    PDB_ID = 0x0202

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader, 16, "StringSt")

    def get_pdb_id(self) -> int:
        return self.PDB_ID
```

Note that Python does not have direct equivalent of Java's `public`, `private` and other access modifiers. The visibility of a class or method in Python is determined by its position within the package (or module). In general, all classes and methods are considered public.

Also note that Python 3.x uses type hints for static analysis purposes only. It does not enforce these types at runtime like Java does with `public` and other access modifiers.