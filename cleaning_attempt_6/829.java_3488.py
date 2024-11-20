class DbgModelTargetSymbolImpl:
    def __init__(self, symbols: 'DbgMinimalSymbol', symbol):
        self.symbols = symbols
        self.symbol = symbol
        self.constant = False
        self.value = None
        self.size = 0

        super().__init__(symbols.model(), symbols, key_symbol(symbol), "Symbol")
        self.symbols.model().add_model_object(self.symbol, self)
        
    @staticmethod
    def index_symbol(symbol):
        return symbol.name()

    @staticmethod
    def key_symbol(symbol):
        return PathUtils.make_key(index_symbol(symbol))

    def change_attributes(self, *args):
        # TODO: DATA_TYPE
        attributes = {
            "NAMESPACE_ATTRIBUTE_NAME": self.symbols,
            "VALUE_ATTRIBUTE_NAME": self.value,
            "SIZE_ATTRIBUTE_NAME": self.size,
            "Name": self.symbol.name(),
            "Size": self.size,
            "TypeId": self.symbol.type_id,
            "Tag": self.symbol.tag
        }
        # TODO: Initialize the attributes

    def is_constant(self):
        return self.constant

    def get_value(self):
        return self.value

    def get_size(self):
        return self.size


class DbgMinimalSymbol:
    pass


class PathUtils:
    @staticmethod
    def make_key(key):
        return key


# Example usage:

symbols = None  # Replace with actual instance of 'DbgModelTargetSymbolContainerImpl'
symbol = DbgMinimalSymbol()  # Replace with actual instance

dbg_model_target_symbol_impl = DbgModelTargetSymbolImpl(symbols, symbol)
