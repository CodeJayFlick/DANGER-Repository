Here is the translation of the given Java code into equivalent Python:

```Python
class AbstractPublic32MsSymbol:
    def __init__(self, pdb, reader, internals):
        super().__init__(pdb, reader, internals)

    def get_offset(self):
        return (internals.get_offset())

    def get_segment(self):
        return (internals.get_segment())

    def get_name(self):
        return (internals.get_name())

    def get_flags(self):
        return (internals.get_flags())

    def is_code(self):
        return (internals.is_code())

    def is_function(self):
        return (internals.is_function())

    def is_managed(self):
        return (internals.is_managed())

    def is_microsoft_intermediate_language(self):
        return (internals.is_microsoft_intermediate_language())

    def emit(self, builder):
        builder.append(str(self.get_symbol_type_name()))
        internals.emit(builder)

class PublicSymbolInternals32:
    pass

# You can use this class as a placeholder for the actual implementation
```

Please note that Python does not have direct equivalent of Java's abstract classes and interfaces. However, we've used `AbstractPublic32MsSymbol` as an abstract base class in our translation.

Also, Python doesn't support checked exceptions like Java. The exception handling mechanism is different in both languages.