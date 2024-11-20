Here is the translation of the Java code to Python:
```
class DebuggerThreadActionContext:
    def __init__(self, trace: object, thread: object):
        self.trace = trace
        self.thread = thread

    @property
    def trace(self) -> object:
        return self._trace

    @property
    def thread(self) -> object:
        return self._thread
```
Note that I've used Python's `@property` decorator to create getter methods for the `trace` and `thread` attributes, which is equivalent to Java's getters. Additionally, I've used type hints (`-> object`) to indicate the types of the `trace` and `thread` attributes.

Also, note that in Python, we don't need a separate class for each attribute like we do in Java (e.g., `getTrace()` method). Instead, we can use properties or direct access to the attributes.