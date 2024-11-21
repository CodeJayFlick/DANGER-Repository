Here is the translation of the Java code to Python:
```
class LabelSearchAddressIterator:
    def __init__(self, label_iterator):
        self.label_iterator = label_iterator

    def has_next(self):
        return self.label_iterator.has_next()

    def next(self):
        symbol = self.label_iterator.next()
        return symbol.get_address()

    def remove(self):
        raise NotImplementedError("Remove operation not supported")

    def __iter__(self):
        return self
```
Note that I've kept the same method names and structure as the original Java code, but translated them to Python syntax. The `remove` method is implemented to raise a `NotImplementedError`, since it's not possible to remove elements from an iterator in Python (unlike in Java).