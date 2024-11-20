class DBTraceBookmarkRegisterSpace:
    def __init__(self, manager, space, thread, frame_level):
        super().__init__(manager, space)
        self.thread = thread
        self.frame_level = frame_level

    @property
    def thread(self):
        return self._thread

    @thread.setter
    def thread(self, value):
        self._thread = value

    @property
    def frame_level(self):
        return self._frame_level

    @frame_level.setter
    def frame_level(self, value):
        self._frame_level = value

class DBTraceBookmarkManager:
    pass  # assuming this class exists elsewhere in the codebase

class AddressSpace:
    pass  # assuming this class exists elsewhere in the codebase

class DBTraceThread:
    pass  # assuming this class exists elsewhere in the codebase
