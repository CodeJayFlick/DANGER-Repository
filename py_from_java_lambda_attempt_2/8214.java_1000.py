Here is the translation of the given Java code into equivalent Python:

```Python
class LocalManagedProcedureMsSymbol:
    PDB_ID = 0x112b

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader)

    @property
    def pdb_id(self) -> int:
        return self.PDB_ID

    @property
    def symbol_type_name(self) -> str:
        return "LMANPROC"
```

Note that Python does not have direct equivalent of Java's `public`, `private` and other access modifiers. The visibility of a class or method in Python is determined by its position within the package (or module). In general, everything defined at the top level of a module is considered public.

Also note that I've used type hints for parameters and return types as per PEP 484 which is the standard way to specify type information in Python.