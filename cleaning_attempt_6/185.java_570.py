class DebuggerStackActionContext:
    def __init__(self, provider, frame, source_component):
        self.frame = frame

    @property
    def frame(self):
        return self._frame

    def __repr__(self):
        return f"DebuggerStackActionContext(frame={self.frame})"
