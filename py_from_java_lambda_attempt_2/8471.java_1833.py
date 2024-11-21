Here is the translation of the given Java code into equivalent Python:

```Python
class OemDefinableString16MsType:
    PDB_ID = 0x0015

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader, 16)

    def get_pdb_id(self) -> int:
        return self.PDB_ID
```

Note that Python does not have direct equivalent of Java's package declaration. In Python, we use modules to organize our code and classes can be defined directly in the module.

Also note that I used type hints for function parameters and return types as per PEP 484 (Type Hints).