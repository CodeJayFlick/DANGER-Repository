class AnyChangeTreeModelListener:
    def tree_changed(self, e):
        pass  # implement your logic here

    def tree_nodes_changed(self, e):
        self.tree_changed(e)

    def tree_nodes_inserted(self, e):
        self.tree_changed(e)

    def tree_nodes_removed(self, e):
        self.tree_changed(e)

    def tree_structure_changed(self, e):
        self.tree_changed(e)
