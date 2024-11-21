class DBTraceEquateRegisterSpace:
    def __init__(self, manager, dbh, space, ent, thread):
        super().__init__(manager, dbh, space, ent)
        self.thread = thread
        self.frame_level = ent.get_frame_level()

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

    def get_thread(self):
        return self.thread

    def get_frame_level(self):
        return self.frame_level
