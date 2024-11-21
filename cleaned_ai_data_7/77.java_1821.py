class DebuggerSnapActionContext:
    def __init__(self, tick):
        self.tick = tick

    @property
    def tick(self):
        return self._tick

# Note: In Python, we don't need a separate `getTick()` method,
# as the property (`@property`) allows us to access the attribute like an attribute.
