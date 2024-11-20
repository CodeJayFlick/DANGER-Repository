Here is the translation of the given Java code into Python:

```Python
class AbstractUserDefinedTypeMsSymbol:
    def __init__(self, pdb, reader, internals):
        super().__init__(pdb, reader)
        self.internals = internals

    @property
    def name(self):
        return self.internals.name()

    @property
    def type_record_number(self):
        return self.internals.type_record_number

    def emit(self, builder):
        builder.append(self.symbol_type_name())
        self.internals.emit(builder)
```

Note that Python does not have direct equivalent of Java's abstract classes and interfaces. However, we can achieve similar functionality using inheritance and polymorphism in Python.

Also note that the `PdbException` is not translated as it is a custom exception class which might require additional code to implement its behavior correctly in Python.