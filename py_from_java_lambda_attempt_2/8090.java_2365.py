Here is the translation of the given Java code into equivalent Python:

```Python
class AbstractPublic16Or3216MsSymbol:
    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader', internals):
        super().__init__(pdb, reader, internals)

    @property
    def offset(self) -> int:
        return (internals).get_offset()

    @property
    def segment(self) -> int:
        return (internals).get_segment()

    @property
    def name(self) -> str:
        return (internals).get_name()

    def emit(self, builder: 'StringBuilder') -> None:
        builder.append(self.get_symbol_type_name())
        self.internals.emit(builder)
```

Note that Python does not have direct equivalent of Java's abstract classes and interfaces. However, we can achieve similar functionality using inheritance and polymorphism in Python.

Also note that the `PdbException` is not directly translated as it seems to be a custom exception class specific to the GHIDRA project.