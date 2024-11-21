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
