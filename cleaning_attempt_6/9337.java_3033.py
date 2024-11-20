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
