Here is the translation of the given Java code into equivalent Python:

```Python
class PendingFunctionGraphViewSettings:
    def __init__(self, copy_settings: 'FunctionGraphViewSettings', perspective):
        super().__init__(copy_settings)

        if not isinstance(perspective, dict) or "vertices" not in perspective or "edges" not in perspective:
            perspective = {"vertices": [], "edges": []}

        self.function_graph_perspective_info = perspective


class FunctionGraphViewSettings:
    pass
```

Note that Python does not have direct equivalent of Java's package declaration. Also, the `FGVertex` and `FGEdge` classes are replaced with a dictionary in this translation as there is no direct equivalent to these types in Python.

Also note that Python 3.6+ has support for type hints using the `->` syntax similar to Java. However, it does not enforce any runtime checks on these types like Java's static type system would.