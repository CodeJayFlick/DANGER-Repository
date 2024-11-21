class TestTargetProcessContainer:
    def __init__(self, parent):
        super().__init__(parent, "Processes", "Processes")

    def add_process(self, pid):
        proc = TestTargetProcess(self, pid)
        self.change_elements([], [proc], {}, "Test Process Added")
        return proc

class DefaultTestTargetObject(metaclass=abc.ABCMeta):
    @abstractmethod
    def __init__(self, parent, name1, name2):
        pass

class TestTargetProcess:
    def __init__(self, container, pid):
        self.container = container
        self.pid = pid

class TestTargetSession:
    pass
