Here is the translation of the Java code to Python:
```
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
```
Note that I've used Python's built-in `dict` type instead of the Java `HashMap`, and also removed some unnecessary comments. Additionally, I've defined a separate `Symbol` class in Python (which is not present in the original Java code), as well as an exception-raising mechanism using Python's built-in exceptions.

Please note that this translation assumes you have already installed the necessary libraries for working with Python, such as `ghidra`.