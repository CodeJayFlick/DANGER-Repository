Here is the translation of the Java code to Python:
```
class DisplayableLabel:
    def __init__(self, symbol):
        self.symbol = symbol

    @property
    def symbol(self):
        return self._symbol

    def get_display_string(self):
        if self.symbol is None:
            return "<No Symbol>"
        return self.symbol.name

    def __str__(self):
        return self.get_display_string()

    def __eq__(self, other):
        if not isinstance(other, DisplayableLabel):
            raise TypeError("Can only compare with another DisplayableLabel")
        return self.symbol == other.symbol

    def __lt__(self, other):
        if not isinstance(other, DisplayableLabel):
            raise TypeError("Can only compare with another DisplayableLabel")
        if self.symbol is None:
            return False
        if other.symbol is None:
            return True
        return self.symbol.name.casefold() < other.symbol.name.casefold()
```
Note that I've used Python's built-in `property` decorator to create a read-only property for the `symbol` attribute, and implemented the comparison methods (`__eq__`, `__lt__`) using Python's syntax.