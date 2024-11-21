Here is the translation of the given Java code into equivalent Python:

```Python
class LldbBreakpointCreatedEvent:
    def __init__(self, info):
        self._bkpt_info = info

    @property
    def breakpoint_info(self):
        return self._bkpt_info


# Example usage:
debug_breakpoint_info = {'some_key': 'some_value'}  # Replace with actual debug breakpoint information
event = LldbBreakpointCreatedEvent(debug_breakpoint_info)
print(event.breakpoint_info)  # Output: {'some_key': 'some_value'}
```

Note that Python does not have direct equivalents for Java's `public`, `private`, and `final` keywords. In this translation, I've used the underscore prefix (`_`) to indicate private variables, as is a common convention in Python.

Also note that Python does not require explicit type definitions like Java does. The equivalent of Java's `extends AbstractLldbEvent<DebugBreakpointInfo>` would be simply defining the class with its methods and properties.