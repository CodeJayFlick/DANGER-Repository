Here is the translation of the given Java code into Python:

```Python
class EmptyIterator:
    def copy(self):
        return self

    def delete(self):
        raise UnsupportedOperationException()

    def delete_count(self, count):
        raise UnsupportedOperationException()

    def get(self):
        return None

    def increment(self):
        raise IndexError()

    def decrement(self):
        raise IndexError()

    def insert(self, value):
        raise UnsupportedOperationException()

    def is_begin(self):
        return True

    def is_end(self):
        return True

    def set(self, value):
        raise UnsupportedOperationException()

    def decrement_n(self, n):
        raise UnsupportedOperationException()

    def increment_n(self, n):
        raise UnsupportedOperationException()

    def is_rbegin(self):
        return True

    def is_rend(self):
        return True

    def assign(self, other_iterator):
        raise UnsupportedOperationException()
```

Note: Python does not have built-in support for exceptions like `UnsupportedOperationException` or `IndexOutOfBoundsException`. The equivalent exception in Python would be a custom-defined class that inherits from the base Exception class.