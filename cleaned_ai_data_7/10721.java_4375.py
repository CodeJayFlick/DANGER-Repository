class GraphAlgorithmStatusListener:
    class STATUS(enum):
        WAITING = 0
        SCHEDULED = 1
        EXPLORING = 2
        BLOCKED = 3
        IN_PATH = 4

    def __init__(self):
        self.total_status_changes = 0

    def status_changed(self, v, s):
        # stub
        pass

    def finished(self):
        # stub
        pass

    def get_total_status_changes(self):
        return self.total_status_changes
