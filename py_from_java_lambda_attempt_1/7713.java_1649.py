Here is the equivalent Python code:

```Python
class FcgFunction:
    def __init__(self, name, entry):
        self.called_functions = set()
        self.calling_functions = set()
        self.entry = entry

    def add_called_function(self, f):
        self.called_functions.add(f)

    def add_caller_function(self, f):
        self.calling_functions.add(f)

    def get_entry_point(self):
        return self.entry

    def get_called_functions(self):
        return frozenset(self.called_functions)

    def get_calling_functions(self):
        return frozenset(self.calling_functions)

    def __str__(self):
        return super().__str__() + f" @ {self.get_entry_point().get_offset()}"
```

Note that Python does not have direct equivalents for Java's `Set` and `TaskMonitor`. Instead, we use the built-in set data structure (`set()`), which is unordered. We also replace `Collections.unmodifiableSet()` with `frozenset()`, which creates an immutable frozenset from a given iterable (like a list or tuple).