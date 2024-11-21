Here is the translation of the Java code to Python:
```
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
```
Note that I've used Python's built-in `property` decorator to create getter and setter methods for the `thread` and `frame_level` attributes. This is equivalent to Java's public getters and setters.

Also, since there are no exceptions thrown in this code (only imports), I didn't include any exception handling logic in the translation.