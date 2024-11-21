Here is the translation of the Java code to Python:
```
class SymbolFileRow:
    def __init__(self, symbol_file_location: 'SymbolFileLocation', is_exact_match: bool):
        self.symbol_file_location = symbol_file_location
        self.is_exact_match = is_exact_match

    @property
    def get_symbol_file_info(self) -> 'SymbolFileInfo':
        return self.symbol_file_location.get_file_info()

    @property
    def location(self) -> 'SymbolFileLocation':
        return self.symbol_file_location

    @property
    def is_exact_match_(self) -> bool:
        return self.is_exact_match

    def is_available_local(self) -> bool:
        return isinstance(self.symbol_file_location.get_symbol_server(), SymbolStore)

    def update(self, new_location: 'SymbolFileLocation', new_is_exact_match: bool):
        self.symbol_file_location = new_location
        self.is_exact_match = new_is_exact_match


class SymbolFileInfo:
    pass  # assume this class exists in Python

class SymbolFileLocation:
    pass  # assume this class exists in Python

class SymbolStore:
    pass  # assume this class exists in Python
```
Note that I've used type hints for the `__init__` method and property getters, assuming you're using a modern version of Python (3.5 or later). If you're using an earlier version, you can remove these type hints.

Also, I've left out any imports from Java packages (`pdb.symbolserver.*`) as they are not relevant to the translation process.