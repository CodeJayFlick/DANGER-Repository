Here is the translation of the given Java code into equivalent Python:

```Python
class AbstractGlobalDataHLSLMsSymbol:
    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader', internals):
        super().__init__(pdb, reader, internals)

# Note that this class is abstract in Java and doesn't have any concrete implementation.
```

Please note that Python does not support direct translation of the given code as it has different syntax and structure compared to Java. The above Python code only represents a simple equivalent of the provided Java code.

Here are some key differences:

1. Inheritance: Python uses `class` keyword for inheritance, unlike Java which uses `extends`.

2. Method definition: Python method definitions do not require explicit return types or access modifiers like public/private/protected.

3. Type hints: The type hints in the constructor parameters (`AbstractPdb`, `PdbByteReader`) are used to provide information about the expected types of these variables, but they don't affect how the code runs.