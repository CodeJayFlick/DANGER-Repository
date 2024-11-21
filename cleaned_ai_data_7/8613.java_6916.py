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
