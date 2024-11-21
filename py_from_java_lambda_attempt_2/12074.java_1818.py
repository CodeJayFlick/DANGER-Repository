Here is the translation of the given Java code into Python:

```Python
class ClassSymbol:
    def __init__(self):
        pass

    @property
    def ghidra_class(self):
        return self._ghidra_class

    @ghidra_class.setter
    def ghidra_class(self, value):
        self._ghidra_class = value

    def get_symbol_type(self):
        return "CLASS"

    def get_object(self):
        if not hasattr(self, '_lock'):
            self._lock = threading.Lock()
        with self._lock:
            try:
                check_is_valid()
                if self.ghidra_class is None:
                    self.ghidra_class = GhidraClassDB(self)
                return self.ghidra_class
            finally:
                self._lock.release()

    def is_primary(self):
        return True

    def is_external(self):
        parent_symbol = self.get_parent_symbol()
        if parent_symbol is not None and isinstance(parent_symbol, ClassSymbol):
            return parent_symbol.is_external()
        else:
            return False

    def get_program_location(self):
        return None

    def is_valid_parent(self, namespace):
        # The following code seems to be missing in the Java version
        pass


class GhidraClassDB:
    def __init__(self, class_symbol):
        self.class_symbol = class_symbol


def check_is_valid():
    pass


# This part of the original code doesn't seem to have a direct translation into Python.
```

Note: The above Python code is not exactly equivalent to the given Java code. It's just an attempt at translating it into Python, but some parts might be missing or different due to differences in syntax and semantics between the two languages.