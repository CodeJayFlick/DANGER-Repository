import threading

class GTreeNode:
    def __init__(self):
        pass  # This class doesn't seem to have any attributes or methods in this snippet.

class GTreeTask:
    def run(self, monitor):
        raise NotImplementedError("Subclasses must implement this method.")

class GTreeExpandAllTask(GTreeTask):
    MAX = 1000

    def __init__(self, tree, node):
        self.tree = tree
        self.node = node

    @staticmethod
    def expand_node(parent, monitor):
        if parent.is_leaf():
            return

        all_children = list(parent.children)
        for child in all_children:
            GTreeExpandAllTask.expand_node(child, monitor)

        monitor.increment_progress(1)


class TaskMonitor:
    def __init__(self):
        pass  # This class doesn't seem to have any attributes or methods in this snippet.

    def initialize(self, value):
        raise NotImplementedError("Subclasses must implement this method.")

    def set_message(self, message):
        raise NotImplementedError("Subclasses must implement this method.")

    def check_canceled(self):
        raise NotImplementedError("Subclasses must implement this method.")

    def increment_progress(self, amount):
        raise NotImplementedError("Subclasses must implement this method.")


def run_on_swing_thread(func):
    threading.Thread(target=func).start()


class GTree:
    @staticmethod
    def is_expanded(tree_path):
        return False  # This class doesn't seem to have any attributes or methods in this snippet.

    @staticmethod
    def expand_path(tree_path, monitor):
        run_on_swing_thread(lambda: None)  # This method seems to be missing.
