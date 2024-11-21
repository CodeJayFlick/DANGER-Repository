class InvertedTreeFilter:
    def __init__(self, tree_filter):
        self.tree_filter = tree_filter

    def accepts_node(self, node):
        return not self.tree_filter.accepts_node(node)

    def show_filter_matches(self):
        return self.tree_filter.show_filter_matches()
