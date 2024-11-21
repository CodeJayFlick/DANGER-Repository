Here is the translation of the given Java code into equivalent Python:

```Python
class LldbBreakpointEnabledEvent:
    def __init__(self, info):
        self.bkpt_info = info

    def get_breakpoint_info(self):
        return self.bkpt_info


# Note: In Python, we don't have a direct equivalent of Java's generics. So the type parameter 'DebugBreakpointInfo' is not included in the class definition.
```

This code defines a `LldbBreakpointEnabledEvent` class with an initializer method (`__init__`) and another method called `get_breakpoint_info`. The `__init__` method takes one argument, `info`, which it assigns to the instance variable `bkpt_info`. The `get_breakpoint_info` method simply returns this value.