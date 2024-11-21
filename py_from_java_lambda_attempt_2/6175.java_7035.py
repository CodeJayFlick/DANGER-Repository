Here's a translation of your Java code into equivalent Python:

```Python
class TestRootNode:
    def __init__(self):
        self.children = []
        for i in range(5):  # Assuming you want 5 leaf nodes initially.
            self.children.append({"name": f"Leaf {i}", "is_leaf": True})

    def get_icon(self, expanded):
        return None

    def get_name(self):
        return "Root"

    def get_tooltip(self):
        return None

    def is_leaf(self):
        return False


# You can create an instance of TestRootNode like this:
root_node = TestRootNode()
```

This Python code does not have direct equivalent to Java's `GTreeNode` and `LeafNode`. Instead, it uses a simple list comprehension in the constructor of `TestRootNode` class. The `get_icon`, `get_name`, `get_tooltip`, and `is_leaf` methods are translated directly from their Java counterparts.

Note that Python does not have direct equivalent to Java's generics (like `<GTreeNode>`), so I used a simpler approach with dictionaries in the list comprehension.