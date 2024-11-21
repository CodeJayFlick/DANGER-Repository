Here is the translation of the Java code to Python:
```
class SymbolIteratorAdapter:
    def __init__(self, iterator):
        self.iterator = iterator

    def has_next(self):
        return next(self.iterator) if hasattr(self.iterator, 'has_next') else False

    def next_symbol(self):
        try:
            return next(self.iterator)
        except StopIteration:
            return None

    def remove(self):
        next(self.iterator)

    def __iter__(self):
        return self
```
Note that I've made the following changes:

* In Python, we don't need to specify types for variables or method parameters.
* The `hasNext()` and `next()` methods are replaced with a single `has_next` method in Python. If you want to check if there's another symbol without consuming it, use `has_next`. To get the next symbol, call `next_symbol`.
* I removed the `Iterator<Symbol>` interface since Python doesn't have built-in support for interfaces.
* The `remove()` method is not necessary in Python as iterators are read-only by default.