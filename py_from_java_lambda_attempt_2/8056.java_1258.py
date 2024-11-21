Here is the translation of the given Java code into equivalent Python:

```Python
class AbstractGlobalManagedDataMsSymbol:
    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader', internals):
        super().__init__(pdb, reader, internals)

# Note that in Python, we don't have a direct equivalent of Java's abstract classes.
# However, the concept is similar. In this case, let's assume you want to create an
# interface for all types of GlobalManagedDataMsSymbol.

class IGlobalManagedDataMsSymbol:
    pass

class AbstractPdb:
    pass

class PdbByteReader:
    pass

class DataSymbolInternals:
    pass

try:
    from pdb import *
except ImportError as e:
    print(f"Error: {e}")
```

Note that Python does not have a direct equivalent of Java's abstract classes. However, the concept is similar. In this case, let's assume you want to create an interface for all types of GlobalManagedDataMsSymbol.

In the above code:

- The `AbstractGlobalManagedDataMsSymbol` class has been translated into a regular Python class.
- Since there are no interfaces in Java that can be directly translated into Python, we have created an abstract base class using the concept of "duck typing" where any object is considered as an instance of this interface if it supports all methods defined by `IGlobalManagedDataMsSymbol`.
- The other classes (`AbstractPdb`, `PdbByteReader`, and `DataSymbolInternals`) are also regular Python classes.