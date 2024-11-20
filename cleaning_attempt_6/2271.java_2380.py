class TestTargetThreadContainer:
    def __init__(self, parent):
        super().__init__(parent, "Threads", "Threads")

    def add_thread(self, tid):
        thread = TestTargetThread(self, tid)
        self.change_elements([], [thread], {}, "Test Thread Added")
        return thread

    def remove_threads(self, threads):
        indices = [target_object.get_index() for target_object in threads]
        self.change_elements(indices, [], {}, "Test Threads Removed")

class TargetObject:
    def get_index(self):
        # implement this method
        pass

class TestTargetThread:
    def __init__(self, parent, tid):
        self.parent = parent
        self.tid = tid

class DefaultTestTargetObject:
    def __init__(self, parent, name1, name2):
        self.parent = parent
        self.name1 = name1
        self.name2 = name2

    def change_elements(self, indices, elements, map, message):
        # implement this method
        pass
