import logging

class GTreeNode:
    def __init__(self, name):
        self.name = name
        self.children = []

    def get_children(self):
        return self.children

    def get_name(self):
        return self.name


class GTreeSelectNodeByNameTask:
    def __init__(self, g_tree, j_tree, names, origin):
        self.g_tree = g_tree
        self.j_tree = j_tree
        self.names = names
        self.origin = origin

    def run(self, monitor):
        if not isinstance(monitor, object):  # equivalent to TaskMonitor in Java
            raise ValueError("Invalid monitor")

        logging.debug(f"Selecting paths: {self.names}")
        node = self.g_tree.get_view_root()

        root_name = names[0]
        if node.name != root_name:
            logging.debug(
                f"When selecting paths by name the first path element must be the "
                f"{root_name} - path: {'.'.join(names)}"
            )
            return

        for i in range(1, len(names)):
            monitor.check_cancelled()
            node = self.find_node_by_name(node, names[i], monitor)
            if node is None:
                logging.debug(f"Could not find node to select - path: {'.'.join(names)}")
                return
            else:
                break

        self.select_path(node.get_tree_path(), monitor)

    def find_node_by_name(self, node, name, monitor):
        for child in node.children:
            if child.name == name:
                return child
        return None

    def select_path(self, tree_path, monitor):
        import threading  # equivalent to runOnSwingThread in Java

        def _select_path():
            nonlocal monitor
            if not monitor.is_cancelled():
                g_tree_selection_model = self.g_tree.get_gtree_selection_model()
                g_tree_selection_model.set_selection_paths([tree_path], self.origin)
                self.j_tree.scroll_path_to_visible(tree_path)

        threading.Thread(target=_select_path).start()


# Example usage:
g_tree = GTreeNode("Root")
j_tree = None  # equivalent to JTree in Java
names = ["Node1", "Node2"]
origin = None  # equivalent to EventOrigin in Java

task = GTreeSelectNodeByNameTask(g_tree, j_tree, names, origin)
monitor = object()  # equivalent to TaskMonitor in Java
try:
    task.run(monitor)
except CancelledException as e:
    logging.error(f"Cancelled: {e}")
