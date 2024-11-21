class AbstractMultiToolTraceListener:
    def __init__(self, trace):
        self.trace = trace
        self.open_in = set()

    def init(self):
        self.trace.add_listener(self)

    def dispose(self):
        self.trace.remove_listener(self)

    def opened_by(self, tool):
        self.open_in.add(tool)

    def closed_by(self, tool):
        self.open_in.remove(tool)
        return not self.open_in
