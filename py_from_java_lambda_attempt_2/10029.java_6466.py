Here's the equivalent Python code:

```Python
class GTestNode:
    def __init__(self, name):
        self.name = name

    def get_name(self):
        return self.name

    def get_icon(self, expanded=False):
        return None  # Return None as there is no icon in this example

    def get_tooltip(self):
        return f"tooltip: {self.name}"

    def is_leaf(self):
        return False
```

Note that Python does not have a direct equivalent to Java's `Icon` class. In the above code, I've returned `None` from the `get_icon` method as there is no icon in this example.