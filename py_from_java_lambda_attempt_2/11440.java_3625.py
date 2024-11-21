Here is the translation of the given Java code into Python:

```Python
class TableEntry:
    def __init__(self, state: int, sym: 'AssemblySymbol', value):
        self.state = state
        self.sym = sym
        self.value = value

    @property
    def getValue(self) -> object:
        return self.value


# For demonstration purposes only. This is not a direct translation of the Java class AssemblySymbol.
class AssemblySymbol:
    pass
```

Please note that Python does not support generics like Java, so I have removed them from the code. Also, I did not translate the `TableEntryKey` class as it was not provided in the given Java code.