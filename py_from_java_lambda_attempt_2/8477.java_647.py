Here is the translation of the given Java code into equivalent Python:

```Python
class OverloadedMethod16MsType:
    PDB_ID = 0x0408

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader, 16, "StringSt")
        reader.skip_padding()

    def get_pdb_id(self) -> int:
        return self.PDB_ID


class AbstractOverloadedMethodMsType:
    pass
```

Note that Python does not have direct equivalent of Java's `public`, `private` and other access modifiers. In Python, everything is public by default.

Also note that the `@Override` annotation in Java has no direct equivalent in Python as it is used to indicate that a method overrides one from its superclass.