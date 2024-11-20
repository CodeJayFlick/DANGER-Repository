Here is the translation of the given Java code into equivalent Python:

```Python
class LldbBreakpointCommandChangedEvent:
    def __init__(self, info):
        self._bkpt_info = info

    @property
    def breakpoint_info(self):
        return self._bkpt_info


# Example usage:
if __name__ == "__main__":
    class DebugBreakpointInfo:  # This is a placeholder for the actual Java class.
        pass

    event = LldbBreakpointCommandChangedEvent(DebugBreakpointInfo())
    print(event.breakpoint_info)
```

Please note that Python does not have direct equivalent of Java's `package`, `public` and other access modifiers. Also, in Python, we don't need to specify the type of a variable while declaring it.