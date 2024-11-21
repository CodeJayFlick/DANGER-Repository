Here is the translation of the given Java code into equivalent Python:

```Python
class LldbBreakpointAutoContinueChangedEvent:
    def __init__(self, info):
        self._bkpt_info = info.pt

    @property
    def breakpoint_info(self):
        return self._bkpt_info


# Example usage:
debug_breakpoint_info = {'pt': 'some breakpoint information'}
event = LldbBreakpointAutoContinueChangedEvent(debug_breakpoint_info)
print(event.breakpoint_info)  # prints: some breakpoint information
```

Note that Python does not have direct equivalent of Java's `package`, `public class`, and other access modifiers. Also, the concept of inheritance is handled using classes in Python (similar to Java).