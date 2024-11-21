class DbgThreadExitedEvent:
    def __init__(self, exit_code):
        self.exit_code = exit_code


# Note: There's no direct equivalent for Java's AbstractDbgEvent class in Python.
# We can create a base class if needed. For simplicity, let's just use the above event class.

class DbgThreadExitedEventWithCode(DbgThreadExitedEvent):
    def __init__(self, exit_code):
        super().__init__(exit_code)
