Here is the translation of the Java code into Python:

```Python
class DeleteTreeCmd:
    def __init__(self, tree_name):
        self.tree_name = tree_name

    def apply_to(self, obj):
        program = Program(obj)
        return program.get_listing().remove_tree(self.tree_name)

    def get_status_msg(self):
        return None

    def get_name(self):
        return f"Delete {self.tree_name}"
```

Note that Python does not have direct equivalents for Java's `package`, `import` statements, or the `public class DeleteTreeCmd implements Command`. The equivalent of a Java class in Python is simply defined using the `class` keyword.