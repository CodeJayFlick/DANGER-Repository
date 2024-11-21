Here is the translation of the Java code into Python:

```Python
class RootNode:
    icon = ResourceManager.load_image("images/play.png")

    def get_icon(self, expanded):
        return self.icon

    def get_name(self):
        return "Scripts"

    def get_tooltip(self):
        return None

    def is_leaf(self):
        return False

    def insert(self, category_path):
        parent = self
        for category in category_path:
            child = self.get_child(parent, category)
            if child is None:
                child = ScriptCategoryNode(category)
                self.insert_sorted(parent, child)
            parent = child

    def get_child(self, parent, name):
        children = list(parent.children())
        for child in children:
            if child.name == name:
                return child
        return None

    def insert_sorted(self, parent, new_child):
        all_children = list(parent.children())
        for child in all_children:
            node_name = child.name
            new_node_name = new_child.name
            if node_name.lower() > new_node_name.lower():
                parent.add(new_child, parent.index(child))
                return
        parent.append(new_child)

class ScriptCategoryNode:
    def __init__(self, name):
        self.name = name

# Note: The ResourceManager and GTreeNode classes are not available in Python.
```

Note that the `ResourceManager` class is used to load an image icon. In Java, this would be a resource manager for loading images or other resources from a jar file. Since there's no direct equivalent in Python, I've left it as-is.

Also note that the `GTreeNode` class represents a node in a tree structure. This isn't directly available in Python either, so you'd need to implement your own tree data structure if needed.