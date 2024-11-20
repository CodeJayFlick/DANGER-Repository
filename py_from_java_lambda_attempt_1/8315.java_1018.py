Here is the translation of the given Java code into equivalent Python:

```Python
class UsingNamespaceMsSymbol:
    PDB_ID = 0x1124

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader, "StringUtf8Nt")

    def get_pdb_id(self) -> int:
        return self.PDB_ID

    def emit(self, builder: str) -> None:
        builder += f"{self.get_symbol_type_name()}: {self.name}"

    def get_symbol_type_name(self) -> str:
        return "UNAMESPACE"


class AbstractPdb:
    pass


class PdbByteReader:
    pass
```

Note that Python does not have direct equivalent of Java's `package`, `public class`, `import` statements. Also, the concept of static variables and methods is different in Python compared to Java.

In this translation:

- The package statement has been removed as it is not directly translatable.
- The public access modifier for classes and methods has also been removed as there are no direct equivalents in Python.
- The import statement has been replaced with class definitions, assuming that the `AbstractPdb` and `PdbByteReader` classes exist elsewhere in your code.