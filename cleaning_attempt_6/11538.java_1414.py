class SymbolScope:
    def __init__(self, parent=None, i=0):
        self.parent = parent
        self.id = i
        self.tree = {}

    @property
    def parent(self):
        return self._parent

    @parent.setter
    def parent(self, value):
        self._parent = value

    def add_symbol(self, symbol: 'Symbol'):
        if symbol.name in self.tree:
            raise SleighException("Duplicate symbol")
        self.tree[symbol.name] = symbol

    def find_symbol(self, name: str) -> 'Symbol':
        return self.tree.get(name)

    @property
    def id(self):
        return self._id

class Symbol:
    pass  # You'll need to define this class further

class SleighException(Exception):
    pass  # You may want to add more functionality here
