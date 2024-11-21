Here is the translation of the given Java code into equivalent Python:

```Python
class AttribLocOrParamReltoAMPMsSymbol:
    PDB_ID = 0x1130

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader)

    @property
    def pdb_id(self) -> int:
        return self.PDB_ID

    @property
    def symbol_type_name(self) -> str:
        return "ATTR_REGREL"
```

Note that Python does not have direct equivalent of Java's `public`, `private` and other access modifiers. In Python, everything is public by default.

Also note the use of type hints in the function definition (`-> None`) which are optional but recommended for better code readability and maintainability.