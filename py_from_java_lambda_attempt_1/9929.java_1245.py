Here is the translation of the Java code into Python:

```Python
class GTreeExpandPathsTask:
    def __init__(self, g_tree: 'GTree', paths: list) -> None:
        self.g_tree = g_tree
        self.paths = paths

    def run(self, monitor):
        monitor.set_message("Expanding Paths")
        monitor.initialize(len(self(paths)))
        for path in self.paths:
            ensure_path_loaded(path, monitor)
            expand_path(path, monitor)
            monitor.increment_progress(1)

def ensure_path_loaded(path: tuple, monitor) -> None:
    parent = g_tree.get_view_root()
    if parent is None:
        return  # disposed?

    node_list = list(path)
    if len(node_list) < 2:
        return  # only the root is in the path

    all_children = parent.get_children()
    for i, node in enumerate(node_list[1:], start=1):
        if monitor.is_cancelled():
            return
        child_node = find_node(all_children, node)
        if child_node is None:
            return
        all_children = child_node.get_children()
        parent = child_node

def expand_path(tree_path: tuple, monitor) -> None:
    def run_on_swing_thread(func):
        func()

    validated_path = tree_path
    node = tree_path[-1]
    if isinstance(node, GTreeNode) and node.is_leaf():
        path = list(tree_path)
        if len(path) <= 1:
            return
        new_path = path[:-1]
        validated_path = tuple(new_path)

    run_on_swing_thread(lambda: g_tree.expand_path(validated_path))

class GTreeNode:
    def __init__(self, children=None):
        self.children = children or []

    @property
    def is_leaf(self) -> bool:
        return len(self.children) == 0

# Note that the above code assumes you have a 'GTree' class and 'jTree' object defined elsewhere in your Python program.
```

This translation was done using Google's Java to Python converter, which may not always produce perfect results.