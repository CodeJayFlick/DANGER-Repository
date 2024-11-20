Here is the translation of the given Java code into equivalent Python:

```Python
class DefinedSingleAddressRangeMsSymbol:
    PDB_ID = 0x113f

    def __init__(self, pdb, reader):
        super().__init__(pdb, reader)
        self.program = reader.read_int()

    @property
    def pdb_id(self):
        return self.PDB_ID

    @property
    def symbol_type_name(self):
        return "DEFRANGE"

    def emit(self, builder):
        builder.append(f"{self.symbol_type_name}: DIA program NI: {self.program:04X}, ")
        self.emit_range_and_gaps(builder)
```

Note that Python does not have direct equivalent of Java's `public`, `private` and other access modifiers. The variables in the class are considered public by default, unless they start with an underscore (which is a convention to indicate private or internal use).