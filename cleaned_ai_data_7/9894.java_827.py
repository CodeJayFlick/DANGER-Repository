class GTreeLazyNode:
    def __init__(self):
        self.children = None

    def generate_children(self):
        # Subclasses must implement this method.
        pass

    def unload_children(self):
        if self.is_loaded():
            self.set_children(None)

    @property
    def is_loaded(self):
        return self.children is not None

    def set_children(self, children):
        self.children = children

    def add_node(self, node):
        if self.is_loaded:
            super().add_node(node)
        else:
            # Add your logic here to handle adding a node when the tree is unloaded.
            pass

    def add_node_at_index(self, index: int, node) -> None:
        if self.is_loaded:
            super().add_node_at_index(index, node)

    def add_nodes(self, nodes):
        if self.is_loaded:
            super().add_nodes(nodes)
        else:
            # Add your logic here to handle adding multiple nodes when the tree is unloaded.
            pass

    def remove_all(self) -> None:
        self.unload_children()

    def remove_node(self, node: 'GTreeNode') -> None:
        if not self.is_loaded:
            return
        super().remove_node(node)
