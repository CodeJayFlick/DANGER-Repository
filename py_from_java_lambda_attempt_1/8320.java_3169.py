Here is the translation of the given Java code into equivalent Python:

```Python
class With16MsSymbol:
    PDB_ID = 0x0108

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader, 16, "StringUtf8St")

    def get_pdb_id(self) -> int:
        return self.PDB_ID

    def get_symbol_type_name(self) -> str:
        return "WITH16"
```

Note that Python does not have direct equivalent of Java's `public`, `private` and other access modifiers. The convention in Python is to use underscore prefix for variables or methods which are intended to be private.

Also, the `@Override` annotation is used in Java to indicate that a method is overriding a method from its superclass. In Python, this concept does not exist as it has no notion of explicit method overriding like Java. Instead, you can simply define the same method name and parameters as your parent class's method.