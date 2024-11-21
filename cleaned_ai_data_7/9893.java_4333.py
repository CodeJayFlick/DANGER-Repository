class GTreeFilterTask:
    def __init__(self, tree: 'GTree', filter: 'GTreeFilter') -> None:
        self.tree = tree
        self.filter = filter
        self.cancelled_programatically = False

    def run(self) -> None:
        if not self.filter:
            self.tree.swing_restore_non_filtered_root_node()
            return
        root = self.tree.model_root
        try:
            monitor.set_message("Loading/Organizing Tree...")
            # disable tree events while loading to prevent unnecessary events from slowing down the operation
            self.tree.set_events_enabled(False)
            node_count = root.load_all(monitor)
            self.tree.set_events_enabled(True)
            monitor.set_message("Filtering...")
            monitor.initialize(node_count)
            filtered_root = root.filter(self.filter, monitor)
            self.tree.swing_set_filtered_root_node(filtered_root)
            if self.filter.show_filter_matches():
                self.expand_in_same_task(monitor, filtered_root)
        except CloneNotSupportedException as e:
            print(f"Got Unexpected CloneNotSupportedException: {e}")
        except CancelledException as e:
            if not self.cancelled_programatically:
                self.tree.run_task(GTreeClearTreeFilterTask(self.tree))
        finally:
            self.tree.set_events_enabled(True)

    def expand_in_same_task(self, monitor, filtered_root):
        expand_task = GTreeExpandAllTask(self.tree, filtered_root)
        expand_task.run(monitor)

    def restore_in_same_task(self, monitor):
        state = self.tree.get_filter_restore_state()
        restore_task = GTreeRestoreTreeStateTask(self.tree, state)
        restore_task.run(monitor)

    def cancel(self) -> None:
        self.cancelled_programatically = True
        super().cancel()

class GTreeNode:
    pass

class GTreeFilter:
    def show_filter_matches(self):
        return False

class TaskMonitor:
    def set_message(self, message: str) -> None:
        print(message)

    def initialize(self, node_count: int) -> None:
        pass
