Here is the translation of the given Java code into equivalent Python:

```Python
class LldbStateListener:
    def __init__(self):
        pass

    def state_changed(self, new_state: str, cause: str) -> None:
        """The state has changed because of the given cause"""
        print(f"New State: {new_state}, Cause: {cause}")

# This is equivalent to Java's default method
LldbStateListener.default_state_changed = LldbStateListener.state_changed

class TriConsumer:
    def __init__(self):
        pass

    @staticmethod
    def accept(old_val, new_val, cause) -> None:
        """The state has changed because of the given cause"""
        print(f"Old State: {old_val}, New State: {new_val}, Cause: {cause}")

# You can use this class as follows:
lldb_state_listener = LldbStateListener()
TriConsumer.accept("OLD_STATE", "NEW_STATE", "CAUSE")
```

Please note that Python does not have direct equivalent of Java's interface. It has abstract classes and interfaces are implemented using abstract methods in Python.