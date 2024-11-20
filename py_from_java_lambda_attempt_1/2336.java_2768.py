Here is the translation of the Java code to Python:
```
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
```
Note that I've made some assumptions about the Python equivalent of Java classes, such as `DBTraceBookmarkManager`, `AddressSpace`, and `DBTraceThread`. In a real-world scenario, you would need to define these classes or import them from other modules.

Also, I've used Python's property decorator (`@property`) to create getter/setter methods for the `thread` and `frame_level` attributes. This is equivalent to Java's accessor methods (e.g., `getThread()` and `setThread(thread)`).