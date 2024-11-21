Here is the translation of the given Java code into equivalent Python:

```Python
class GlobalProcedureIa64IdMsSymbol:
    PDB_ID = 0x114b

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader, "StringUtf8Nt")

    def get_pdb_id(self) -> int:
        return self.PDB_ID

    def get_symbol_type_name(self) -> str:
        return "GPROCIA64_ID"

    def get_special_type_string(self) -> str:
        return "ID"
```

Note that Python does not have direct equivalent of Java's `public`, `private` and other access modifiers. In Python, everything is public by default.

Also note the use of type hints in the function definitions (`-> None` for example). These are optional but can be useful for static analysis tools or IDEs to understand the types used in your code.