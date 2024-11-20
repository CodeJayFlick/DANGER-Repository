Here is a translation of the Java code into equivalent Python:

```Python
class GTreeLoadChildrenTask:
    def __init__(self, tree, node):
        self.tree = tree
        self.node = node

    def run(self, monitor):
        progress_value = monitor.progress()
        max_value = monitor.max_progress()
        monitor.set_message("Loading children")
        try:
            self.node.children = self.node.generate_children(monitor)
        except Exception as e:  # CancelledException is not available in Python
            if not self.tree.is_disposed():
                import threading
                def collapse_tree():
                    self.tree.collapse_all(self.tree.view_root())
                threading.Thread(target=collapse_tree).start()
            self.node.unload_children()

        finally:
            monitor.initialize(max_value)
            monitor.set_progress(progress_value)

class GTreeSlowLoadingNode:
    def generate_children(self, monitor):
        # implement this method
        pass

    def set_children(self, children):
        # implement this method
        pass

    def unload_children(self):
        # implement this method
        pass

# usage example
tree = ...  # create a tree object
node = GTreeSlowLoadingNode()  # create a node object
task = GTreeLoadChildrenTask(tree, node)
```

Please note that Python does not have direct equivalents for Java's `CancelledException` and the Swing-based threading model. The code above uses Python's built-in exception handling mechanism to catch any exceptions during execution of the task.