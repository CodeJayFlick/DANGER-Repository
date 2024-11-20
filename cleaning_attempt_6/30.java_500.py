class TraceRecorderAdvancedPluginEvent:
    NAME = "Recorder Advanced"

    def __init__(self, source: str, recorder: 'TraceRecorder', snap: int):
        super().__init__(source, self.NAME)
        self.recorder = recorder
        self.snap = snap

    @property
    def recorder(self) -> 'TraceRecorder':
        return self._recorder

    @recorder.setter
    def recorder(self, value: 'TraceRecorder'):
        self._recorder = value

    @property
    def snap(self) -> int:
        return self._snap

    @snap.setter
    def snap(self, value: int):
        self._snap = value
