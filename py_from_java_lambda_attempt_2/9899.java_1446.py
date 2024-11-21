Here is the translation of the Java code into Python:

```Python
class GTreeState:
    MAX_ITEM_COUNT = 50

    def __init__(self, tree):
        self.tree = tree
        self.expanded_paths = list(tree.get_expanded_paths())
        self.selection_paths = get_selection_paths(self.tree)
        self.view_paths = get_view_paths()

        adjust_paths_for_size_constraint()

    @staticmethod
    def do_adjust_paths_for_size_constraint():
        max_item_count = GTreeState.MAX_ITEM_COUNT
        combined_size = len(GTreeState.expanded_paths) + len(GTreeState.selection_paths)

        if combined_size < max_item_count:
            return

        limited_view_paths = get_limited_view_paths(max_item_count)
        GTreeState.expanded_paths = list(limited_view_paths)

        if len(GTreeState.selection_paths) > max_item_count:
            GTreeState.selection_paths &= set(limited_view_paths)
        else:
            GTreeState.expanded_paths.extend(GTreeState.selection_paths)


    def get_expanded_paths(self):
        return tuple(GTreeState.expanded_paths)

    def get_selected_paths(self):
        return tuple(GTreeState.selection_paths)

    @staticmethod
    def update_path_for_moved_node(path):
        node = path[-1]
        return node.get_tree_path()

    def update_state_for_moved_nodes(self):
        for i in range(len(GTreeState.expanded_paths)):
            GTreeState.expanded_paths[i] = self.update_path_for_moved_node(GTreeState.expanded_paths[i])

        for i in range(len(GTreeState.selection_paths)):
            GTreeState.selection_paths[i] = self.update_path_for_moved_node(GTreeState.selection_paths[i])


    def is_empty(self):
        return not (GTreeState.selection_paths or GTreeState.expanded_paths)


    @staticmethod
    def get_selection_paths(node, tree=None):
        if node == tree.get_view_root():
            return list(tree.get_selection_paths())

        selection_paths = []
        for path in tree.get_selection_paths():
            if node.get_tree_path().is_descendant(path):
                selection_paths.append(node.get_tree_path())
        return selection_paths


    @staticmethod
    def get_some_view_paths(limit=5, tree=None):
        view_rect = tree.get_view_rect()
        jtree = tree.get_jtree()

        top_row = jtree.get_closest_row_for_location(view_rect.x, view_rect.y)
        bottom_row = jtree.get_closest_row_for_location(view_rect.x, view_rect.y + view_rect.height)

        top -= 1
        bottom += 1

        end = bottom - limit
        end = max(end, top)  # constrain 'end' when the limit is larger than the view size

        result = set()
        for i in range(bottom, end, -1):
            path = jtree.get_path_for_row(i)
            if not path:
                continue
            result.add(path)

        return list(result)


    def __str__(self):
        selection_paths_str = ', '.join(map(str, self.selection_paths))
        expanded_paths_str = ', '.join(map(str, self.expanded_paths))

        return f"GTreeState[Selection: {selection_paths_str}, Expansion: {expanded_paths_str}]"


def get_selection_paths(node, tree=None):
    if node == tree.get_view_root():
        return list(tree.get_selection_paths())

    selection_paths = []
    for path in tree.get_selection_paths():
        if node.get_tree_path().is_descendant(path):
            selection_paths.append(node.get_tree_path())
    return selection_paths


def get_limited_view_paths(limit, view_rect=None, jtree=None):
    result = set()
    for i in range(view_rect.height - 1, -1, -1):
        path = jtree.get_path_for_row(i)
        if not path:
            continue
        result.add(path)

    return list(result)


if __name__ == "__main__":
    # Testing code
    tree = GTree()  # Assuming you have a class 'GTree'
    state = GTreeState(tree, tree.get_view_root())
```

Please note that this is just one possible translation of the Java code into Python. The actual implementation may vary depending on your specific requirements and constraints.