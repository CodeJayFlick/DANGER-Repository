Here is the translation of the given Java code into equivalent Python:

```Python
class AbstractGlobalProcedureStartMipsMsSymbol:
    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader', internals):
        super().__init__(pdb, reader, internals)

    @property
    def special_type_string(self) -> str:
        return "Type"

# This is equivalent to the Java interface or abstract class declaration.
class ProcedureStartMipsSymbolInternals:
    pass

class PdbException(Exception):
    pass

class AbstractPdb:
    pass

class PdbByteReader:
    pass
```

Please note that Python does not have direct equivalents for some of the Java constructs like `abstract`, `public`, `throws` etc. Also, Python's type hinting is different from Java's and it uses a syntax similar to Java 8+ but with more flexibility.