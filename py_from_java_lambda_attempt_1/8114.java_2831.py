Here is the translation of the given Java code into equivalent Python:

```Python
class AttribLocOrParamReltoVFPMsSymbol:
    PDB_ID = 0x112e

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader)

    @property
    def pdb_id(self) -> int:
        return self.PDB_ID

    @property
    def symbol_type_name(self) -> str:
        return "ATTR_ MANFRAMEREL"

class AbstractLocalOrParameterRelativeToVirtualFramePointerMsSymbol:
    pass

class PdbByteReader:
    pass

class AbstractPdb:
    pass

# Example usage:

pdb = None  # Replace with your implementation of AbstractPdb
reader = None  # Replace with your implementation of PdbByteReader

symbol = AttribLocOrParamReltoVFPMsSymbol(pdb, reader)
print(symbol.pdb_id)  # prints: 0x112e
print(symbol.symbol_type_name)  # prints: ATTR_ MANFRAMEREL
```

Please note that Python does not have direct equivalent of Java's `package`, `public class`, etc. keywords. Also, the concept of inheritance is handled using classes and their parent-child relationships in Python.