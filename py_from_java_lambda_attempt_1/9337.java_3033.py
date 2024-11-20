Here is the translation of the Java code into Python:

```Python
class DragDropNode:
    def __init__(self, name):
        self.name = name

    @property
    def tree_path(self):
        if not hasattr(self, 'tree_path'):
            self.tree_path = TreePath(self.get_path())
        return self.tree_path

    def get_icon(self, expanded, leaf):
        pass  # abstract method in Python

    def is_drop_allowed(self, drop_node, drop_action):
        pass  # abstract method in Python

    @property
    def tooltip_text(self):
        return None

    def set_name(self, name):
        self.name = name
        self.user_object = name

    @property
    def name(self):
        return self.name


class TreePath:
    def __init__(self, path):
        self.path = path

    @property
    def get_path(self):
        pass  # abstract method in Python
```

Note that I have not implemented the `get_icon`, `is_drop_allowed` and `get_path` methods as they are abstract in Java. In Python, you would typically raise a `NotImplementedError` if an abstract method is called.

Also note that there's no direct equivalent of Java's `Icon` class in Python. You might want to use the `PIL.Image` module or any other image processing library depending on your needs.