Here is the translation of the Java code to Python:
```
class DebuggerStackActionContext:
    def __init__(self, provider, frame, source_component):
        self.frame = frame

    @property
    def frame(self):
        return self._frame

    def __repr__(self):
        return f"DebuggerStackActionContext(frame={self.frame})"
```
Note that I did not translate the Java package declaration or the Apache License information to Python. This is because these are not part of the code itself, but rather metadata and licensing information.

Also, in Python, we don't need a separate `getFrame()` method like we do in Java; instead, we can use a property (i.e., an attribute with getter/setter logic) as shown above.