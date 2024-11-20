class TypeFilteredSymbolIterator:
    def __init__(self, it, type):
        self.it = it
        self.type = type
        self.next_symbol = None

    def has_next(self):
        if self.next_symbol is not None:
            return True
        return self.find_next()

    def next(self):
        if self.has_next():
            symbol = self.next_symbol
            self.next_symbol = None
            return symbol
        return None

    def find_next(self):
        while self.it.has_next():
            symbol = self.it.next()
            if symbol.get_symbol_type() == self.type:
                self.next_symbol = symbol
                return True
        return False

    def remove(self):
        raise NotImplementedError("remove is not implemented")

    def __iter__(self):
        return self


# Example usage:

class SymbolIterator:
    def has_next(self):
        pass  # implement this method in your actual code

    def next(self):
        pass  # implement this method in your actual code

class SymbolType:
    pass  # implement this class and its methods in your actual code

class Symbol:
    def get_symbol_type(self):
        pass  # implement this method in your actual code
