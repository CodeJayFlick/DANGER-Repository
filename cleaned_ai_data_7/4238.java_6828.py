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
