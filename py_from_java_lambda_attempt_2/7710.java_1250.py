Here is the translation of the given Java code into Python:

```Python
class FunctionEdgeCache:
    def __init__(self):
        self.all_edges_by_function = {}
        self.tracked = set()

    def get(self, f):
        return self.all_edges_by_function.get(f)

    def is_tracked(self, f):
        return f in self.tracked

    def set_tracked(self, f):
        self.tracked.add(f)
```

Note that Python does not have a direct equivalent to Java's `Map` and `Set`. Instead, we use dictionaries (`{}`) for mapping and sets (using the built-in `set()` function or the `{}` syntax).