Here is the translation of the given Java code into equivalent Python:

```Python
class LldbBreakpointThreadChangedEvent:
    def __init__(self, info):
        self._bkpt_info = info

    @property
    def breakpoint_info(self):
        return self._bkpt_info


# Note: In Python, we don't have a direct equivalent of Java's "extends" keyword.
# The AbstractLldbEvent class is not defined in the given code snippet. If it exists elsewhere,
# you would need to import and use that class here.

class DebugBreakpointInfo:
    def __init__(self):
        pass

    @property
    def pt(self):
        return None  # Replace with actual implementation


def main():
    info = DebugBreakpointInfo()
    event = LldbBreakpointThreadChangedEvent(info)
    breakpoint_info = event.breakpoint_info
    print(breakpoint_info)


if __name__ == "__main__":
    main()

```

This Python code defines two classes: `LldbBreakpointThreadChangedEvent` and `DebugBreakpointInfo`. The `LldbBreakpointThreadChangedEvent` class has an initializer that takes a `DebugBreakpointInfo` object as input, stores it in the `_bkpt_info` attribute, and provides a property to access this information.