Here is the translation of the given Java code into Python:

```Python
class CodeUnitKeyIterator:
    def __init__(self, code_mgr, it, forward):
        self.code_mgr = code_mgr
        self.it = it
        self.forward = forward
        self.next_cu = None

    def remove(self):
        raise UnsupportedOperationException()

    def has_next(self):
        if not hasattr(self, 'next_cu') or self.next_cu is None:
            self.find_next()
        return getattr(self, 'next_cu', False)

    def next(self):
        if self.has_next():
            ret = self.next_cu
            setattr(self, 'next_cu', None)
            return ret
        return None

    def find_next(self):
        while not hasattr(self, 'next_cu') or self.next_cu is None:
            addr = None
            if self.forward and self.it.hasNext():
                addr = next(self.it)
            elif not self.forward and self.it.hasPrevious():
                addr = prev(self.it)
            if addr is not None:
                self.next_cu = self.code_mgr.get_code_unit_at(addr)

    def __iter__(self):
        return self

class UnsupportedOperationException(Exception): pass
```

Note: Python does not have a direct equivalent of Java's `Iterator` interface. Instead, we can use the built-in iterator protocol in Python to implement iteration over an object.