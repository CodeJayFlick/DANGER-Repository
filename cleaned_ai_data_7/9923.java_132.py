class GTreeBulkTask:
    def __init__(self, tree):
        pass  # equivalent to super(tree)

    def run(self, monitor):
        filtering_enabled = tree.is_filtering_enabled()

        try:
            if filtering_enabled:
                self.enable_filter(False)
            self.run_bulk(monitor)
        finally:
            if filtering_enabled:
                self.enable_filter(True)

    def enable_filter(self, enable):
        import threading
        thread = threading.Thread(target=lambda: setattr(tree, 'filtering_enabled', enable))
        thread.start()

    def run_bulk(self, monitor):  # abstract method in Java, equivalent to a pure virtual function in C++
        pass  # implement this method according to your needs

class GTree:
    def is_filtering_enabled(self):
        pass  # implement this method according to your needs
