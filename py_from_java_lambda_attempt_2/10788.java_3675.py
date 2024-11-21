Here is the translation of the Java interface `VertexTooltipProvider` to a Python class:

```python
class VertexTooltipProvider:
    def __init__(self):
        pass

    def get_tooltip(self, v):
        """Returns a tooltip component for the given vertex"""
        # TO DO: implement this method in your subclass
        raise NotImplementedError("Subclasses must implement this method")

    def get_tooltip(self, v, e):
        """Returns a tooltip component for the given vertex and edge"""
        # TO DO: implement this method in your subclass
        raise NotImplementedError("Subclasses must implement this method")

    def get_tooltip_text(self, v, e):
        """Returns a tooltip string for the given vertex and mouse event"""
        # TO DO: implement this method in your subclass
        raise NotImplementedError("Subclasses must implement this method")
```

Note that I've used Python's `raise` statement to indicate where you would need to add implementation details. In Java, interfaces are abstract by definition, so it makes sense to translate them into Python classes with similar behavior.

Also note that the type parameters `<V>` and `<E>` have been removed in this translation, as they do not exist in Python's syntax for defining classes or methods.