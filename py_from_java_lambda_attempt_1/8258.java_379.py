Here is the translation of the given Java code into equivalent Python:

```Python
class ManyRegisterVariableStMsSymbol:
    PDB_ID = 0x1005

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader, 32, "StringUtf8St")

    def get_pdb_id(self) -> int:
        return self.PDB_ID

    def get_symbol_type_name(self) -> str:
        return "MANYREG_ST"
```

Note that Python does not have direct equivalent of Java's `public`, `private` and other access modifiers. The concept is similar, but the implementation differs.

Also note that in Python, we don't need to specify types for method parameters or return values like we do in Java. This makes the code more concise and easier to read.