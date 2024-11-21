class DBTraceDefinedDataRegisterView(DBTraceDefinedDataView):
    def __init__(self, space: 'DBTraceCodeSpace'):
        super().__init__(space)

    def get_thread(self) -> 'ghidra.trace.model.thread.TraceThread':
        return self.space.get_thread()
