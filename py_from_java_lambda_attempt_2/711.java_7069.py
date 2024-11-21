Here is the translation of the Java code to Python:
```
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
```
Note that I've used Python's type hinting feature to indicate the expected types of the `state`, `thread`, and `frame` parameters. However, since we're not actually using any Java-specific classes or interfaces here, these hints are purely for documentation purposes.

Also, I didn't implement the `DbgState`, `DbgThread`, and `DbgStackFrameImpl` classes in full, as they were not provided with their own implementation details. You can add attributes and methods to these classes as needed based on your specific use case.