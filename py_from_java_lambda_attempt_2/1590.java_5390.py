Here is the translation of the given Java code into equivalent Python:

```Python
class LldbBreakpointLocationsRemovedEvent:
    def __init__(self, info):
        self.bkpt_info = info

    @property
    def breakpoint_info(self):
        return self.bkpt_info


# Example usage:
debug_breakpoint_info = {'some_key': 'some_value'}  # Replace with actual debug breakpoint information
event = LldbBreakpointLocationsRemovedEvent(debug_breakpoint_info)
print(event.breakpoint_info)  # Output: {'some_key': 'some_value'}
```

In this translation, I've used Python's class-based object-oriented programming to create a `LldbBreakpointLocationsRemovedEvent` class. The constructor (`__init__`) takes an argument `info`, which is stored as the instance variable `bkpt_info`. 

The `getBreakpointInfo()` method from Java has been replaced with a property decorator in Python, allowing you to access the breakpoint information using dot notation (e.g., `event.breakpoint_info`).