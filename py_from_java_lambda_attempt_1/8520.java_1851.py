Here is the translation of the given Java code into equivalent Python:

```Python
class VirtualFunctionTablePointerWithOffsetMsType:
    PDB_ID = 0x140c

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader, 32, 2)

    def get_pdb_id(self) -> int:
        return self.PDB_ID
```

Note that Python does not have direct equivalent of Java's `public`, `private` and other access modifiers. In Python, everything is public by default.

Also note the use of type hints in the function definitions (`def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:`). These are not enforced at runtime but can be used for static analysis or IDE code completion.