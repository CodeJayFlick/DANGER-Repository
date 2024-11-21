class TraceMemoryStatePcodeExecutorStatePiece:
    def __init__(self, trace: 'ghidra.trace.model.Trace', snap: int, thread: 'ghidra.trace.model.thread.TraceThread', frame: int):
        self.unique = {}
        self.viewport = DefaultTraceTimeViewport(trace)
        self.viewport.set_snap(snap)

    @property
    def trace(self) -> 'ghidra.trace.model.Trace':
        return self._trace

    @trace.setter
    def trace(self, value: 'ghidra.trace.model.Trace'):
        self._trace = value

    @property
    def snap(self) -> int:
        return self._snap

    @snap.setter
    def snap(self, value: int):
        self._snap = value
        self.viewport.set_snap(value)

    @property
    def thread(self) -> 'ghidra.trace.model.thread.TraceThread':
        return self._thread

    @thread.setter
    def thread(self, value: 'ghidra(trace).model(thread).TraceThread'):
        if value is not None and value.get_trace() != self.trace:
            raise ValueError("Thread must be part of the same trace")
        self._thread = value

    @property
    def frame(self) -> int:
        return self._frame

    @frame.setter
    def frame(self, value: int):
        self._frame = value

    def range(self, offset: int, size: int) -> tuple[int]:
        return (offset, offset + size)

    def get_trace(self) -> 'ghidra.trace.model.Trace':
        return self.trace

    def set_snap(self, snap: int):
        self.snap = snap
        self.viewport.set_snap(snap)

    def get_snap(self) -> int:
        return self.snap

    def set_thread(self, thread: 'ghidra(trace).model(thread).TraceThread'):
        if thread is not None and thread.get_trace() != self.trace:
            raise ValueError("Thread must be part of the same trace")
        self.thread = thread

    def get_thread(self) -> 'ghidra(trace).model(thread).TraceThread':
        return self.thread

    def set_frame(self, frame: int):
        self.frame = frame

    def get_frame(self) -> int:
        return self.frame
