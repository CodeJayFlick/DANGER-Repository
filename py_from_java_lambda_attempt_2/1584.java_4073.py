Here is the translation of the given Java code into equivalent Python:

```Python
class LldbBreakpointDisabledEvent:
    def __init__(self, info):
        self.bkpt_info = info

    def get_breakpoint_info(self):
        return self.bkpt_info


# Define a class for DebugBreakpointInfo (assuming it's not available in the standard library)
class DebugBreakpointInfo:
    pass
```

Please note that Python does not have direct equivalent of Java classes like `package`, `public`, `private` etc. Also, there is no need to specify return types while defining methods as they are inferred by Python itself.

In this translation:

- The class `LldbBreakpointDisabledEvent` has been defined with an initializer method (`__init__`) that takes one argument.
- A property `bkpt_info` has been added which stores the breakpoint information passed in the constructor.
- Another method `get_breakpoint_info` is used to retrieve this stored breakpoint information.

The class `DebugBreakpointInfo` has also been defined, assuming it's not available in Python standard library.