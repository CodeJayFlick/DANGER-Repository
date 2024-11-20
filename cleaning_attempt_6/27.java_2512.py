class TraceClosedPluginEvent:
    NAME = "Trace Closed @"

    def __init__(self, source, trace):
        super().__init__(source, f"{NAME}{hex(id(trace))}")
        self.trace_ref = weakref.ref(trace)

    def get_trace(self):
        return self.trace_ref()
