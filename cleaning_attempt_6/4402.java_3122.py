class SymbolFilter:
    def __init__(self):
        pass

    def accepts(self, symbol: 'ghidra.program.model.symbol.Symbol', program: 'ghidra.program.model.listing.Program') -> bool:
        raise NotImplementedError("Subclasses must implement this method")

    def accepts_only_code_symbols(self) -> bool:
        raise NotImplementedError("Subclasses must implement this method")

    def accepts_default_label_symbols(self) -> bool:
        raise NotImplementedError("Subclasses must implement this method")

    def accepts_all(self) -> bool:
        raise NotImplementedError("Subclasses must implement this method")
