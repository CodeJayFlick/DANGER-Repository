Here is the translation of the given Java code into equivalent Python:

```Python
class EndArgumentsListMsSymbol:
    PDB_ID = 0x000a

    def __init__(self, pdb, reader):
        super().__init__(pdb, reader)
        self.record_length = reader.get_limit() - reader.get_index()

    def get_pdb_id(self):
        return self.PDB_ID

    def emit(self, builder):
        builder.append(f"{self.symbol_type_name()}, Length = 0x{self.record_length:x}")

    def get_symbol_type_name(self):
        return "ENDARG"


class AbstractPdb:
    pass


class PdbByteReader:
    def __init__(self):
        self.limit = None
        self.index = None

    def get_limit(self):
        return self.limit

    def get_index(self):
        return self.index
```

Please note that Python does not have direct equivalent of Java's `package`, so I did not include any package declaration in the above code. Also, Python is an interpreted language and it doesn't support static type checking like Java.