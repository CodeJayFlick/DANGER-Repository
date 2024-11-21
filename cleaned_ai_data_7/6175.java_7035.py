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
