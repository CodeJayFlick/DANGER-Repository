class DBTraceUndefinedDataRegisterView(DBTraceUndefinedDataView):
    def __init__(self, space: 'DBTraceCodeSpace'):
        super().__init__(space)

    def get_thread(self) -> 'TraceThread':
        return self.space.get_thread()
