Here is the translation of the Java code into Python:

```Python
class ViewChangedPluginEvent:
    NAME = "ViewChanged"

    def __init__(self, source: str, tree_name: str, view_set):
        self.source = source
        self.tree_name = tree_name
        self.view_set = view_set

    @property
    def get_tree_name(self) -> str:
        return self.tree_name

    @property
    def get_view(self) -> set:
        return self.view_set

    def __str__(self):
        return f"Tree Name={self.tree_name}, AddressSet={self.view_set}"
```

Note that Python does not have direct equivalent of Java's `public` and `private`. In Python, everything is public by default. If you want to restrict access to certain attributes or methods, you can use the underscore prefix (e.g., `_tree_name`) for internal variables or double underscore prefix (`__get_tree_name`) for private methods.

Also note that in Java, there are specific classes like `AddressSet` and interfaces like `PluginEvent`, which do not have direct equivalent in Python. In this translation, I assumed these to be simple data structures (like sets) and event types (like strings), respectively.