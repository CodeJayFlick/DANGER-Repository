Here is the translation of the Java code to Python:
```
class SymbolRowObjectToProgramLocationTableRowMapper:
    def map(self, symbol: 'Symbol', program: 'Program') -> 'ProgramLocation':
        return symbol.get_program_location()
```
Note that I've kept the type hints in the Python version as well, since they can be useful for documentation and static analysis. However, if you prefer to remove them, the code would simply become:
```
class SymbolRowObjectToProgramLocationTableRowMapper:
    def map(self, symbol, program) -> 'ProgramLocation':
        return symbol.get_program_location()
```