Here's the equivalent Python code:

```Python
class LocalVariableSymbolNode:
    LOCAL_VARIABLE_ICON = None  # Initialize icon as None

    def __init__(self, program, symbol):
        super().__init__(program, symbol)

    @property
    def icon(self):
        return self.LOCAL_VARIABLE_ICON

    def set_node_cut(self, is_cut=False):
        raise ValueError("Cannot cut a local variable node")
```

Note that Python does not have direct equivalents for Java's `Icon` class or the `@Override` annotation. In this translation, I've used a simple property to represent the icon and raised a `ValueError` instead of an `UnsupportedOperationException`.