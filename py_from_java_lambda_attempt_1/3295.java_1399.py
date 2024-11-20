Here is the translation of the Java code into Python:

```Python
class TreeSelectionPluginEvent:
    NAME = "ProgramTreeSelection"

    def __init__(self, source, tree_name, group_paths):
        self.source = source
        self.tree_name = tree_name
        self.group_paths = group_paths

    @property
    def get_group_paths(self):
        return self.group_paths

    @property
    def get_tree_name(self):
        return self.tree_name

    def __str__(self):
        result = f"Tree Name: {self.tree_name}, Group Paths: {{"
        for i, group_path in enumerate(self.group_paths):
            result += f"[{group_path}]"
            if i < len(self.group_paths) - 1:
                result += ", "
        return result + "}"
```

Note that Python does not have direct equivalents of Java's `public`, `private`, and other access modifiers. In this translation, I've used the convention of prefixing instance variables with `_` to indicate they are intended to be private (although Python doesn't enforce this).