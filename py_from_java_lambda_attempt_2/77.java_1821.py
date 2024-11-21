Here is the translation of the Java code to Python:
```
class DebuggerSnapActionContext:
    def __init__(self, tick):
        self.tick = tick

    @property
    def tick(self):
        return self._tick

# Note: In Python, we don't need a separate `getTick()` method,
# as the property (`@property`) allows us to access the attribute like an attribute.
```
Note that I didn't include any imports or licensing information in this translation, as these are not part of the code itself.