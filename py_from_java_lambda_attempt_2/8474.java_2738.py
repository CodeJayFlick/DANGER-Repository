Here is the translation of the given Java code into equivalent Python:

```Python
class OneMethod16MsType:
    PDB_ID = 0x040c

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader, 16, "StringSt")

    def get_pdb_id(self) -> int:
        return self.PDB_ID
```

Note that Python does not have direct equivalent of Java's package declaration. In Python, you can use modules to organize your code but it is not necessary for this translation.

Also note that in the `__init__` method, I used type hints (`'AbstractPdb'`, `'PdbByteReader'`) which are a feature available in Python 3.5 and later versions. If you're using an earlier version of Python, you can remove these type hints without affecting the functionality.

Lastly, note that there is no direct equivalent to Java's `@Override` annotation in Python. The method overriding mechanism works similarly but it does not require explicit declaration like in Java.