class DebuggerThreadActionContext:
    def __init__(self, trace: object, thread: object):
        self.trace = trace
        self.thread = thread

    @property
    def trace(self) -> object:
        return self._trace

    @property
    def thread(self) -> object:
        return self._thread
