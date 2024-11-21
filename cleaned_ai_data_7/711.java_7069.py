class DbgThreadSelectedEvent:
    def __init__(self, state: 'DbgState', thread: 'DbgThread', frame: 'DbgStackFrameImpl'):
        self.id = thread.get_id()
        self.state = state
        self.thread = thread
        self.frame = frame

    @property
    def thread_id(self):
        return self.id

    @property
    def dbg_state(self):
        return self.state

    @property
    def dbg_thread(self):
        return self.thread

    @property
    def dbg_frame(self):
        return self.frame


class DbgState:
    pass  # Not implemented in this example, but you can add attributes and methods as needed


class DbgThread:
    def get_id(self) -> int:
        raise NotImplementedError("Must be implemented")


class DbgStackFrameImpl:
    pass  # Not implemented in this example, but you can add attributes and methods as needed
