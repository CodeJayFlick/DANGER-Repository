Here is the equivalent Python code:

```Python
class GdbStateChangeRecord:
    def __init__(self, inferior: 'GdbInferior', affected_threads: list['GdbThread'], state: 'GdbState',
                 event_thread: 'GdbThread', cause: 'GdbCause', reason: 'GdbReason'):
        self.inferior = inferior
        self.affected_threads = affected_threads
        self.state = state
        self.event_thread = event_thread
        self.cause = cause
        self.reason = reason

    @property
    def inferior(self):
        return self._inferior

    @inferior.setter
    def inferior(self, value):
        self._inferior = value

    @property
    def affected_threads(self):
        return self._affected_threads

    @affected_threads.setter
    def affected_threads(self, value):
        self._affected_threads = value

    @property
    def state(self):
        return self._state

    @state.setter
    def state(self, value):
        self._state = value

    @property
    def event_thread(self):
        return self._event_thread

    @event_thread.setter
    def event_thread(self, value):
        self._event_thread = value

    @property
    def cause(self):
        return self._cause

    @cause.setter
    def cause(self, value):
        self._cause = value

    @property
    def reason(self):
        return self._reason

    @reason.setter
    def reason(self, value):
        self._reason = value


class GdbInferior:
    pass


class GdbThread:
    pass


class GdbState:
    pass


class GdbCause:
    pass


class GdbReason:
    pass
```

Note that I've used Python's built-in `list` type to represent the collection of threads, as Java's `Collection` interface doesn't have a direct equivalent in Python.