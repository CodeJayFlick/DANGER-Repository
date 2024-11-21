class AbstractReferenceMsSymbol:
    def __init__(self, pdb, reader, internals):
        super().__init__()
        self.internals = internals

    @property
    def sum_name(self):
        return self.internals.sum_name

    @property
    def offset_actual_symbol_in_dollar_dollar_symbols(self):
        return self.internals.offset_actual_symbol_in_dollar_dollar_symbols

    @property
    def module_index(self):
        return self.internals.module_index

    def emit(self, builder):
        builder.append(self.symbol_type_name)
        self.internals.emit(builder)

class ReferenceSymbolInternals:
    def __init__(self):
        pass  # Initialize internals here if needed

    def get_sum_name(self):
        raise NotImplementedError("Subclasses must implement this method")

    def get_offset_actual_symbol_in_dollar_dollar_symbols(self):
        raise NotImplementedError("Subclasses must implement this method")

    def get_module_index(self):
        raise NotImplementedError("Subclasses must implement this method")

    def emit(self, builder):
        raise NotImplementedError("Subclasses must implement this method")
