Here is the translation of the Java code to Python:
```
class LldbBreakpointHitEvent:
    def __init__(self, info):
        self.info = info

# Note: In Python, we don't need a separate class for DebugProcessInfo
debug_process_info = object  # or any other suitable placeholder

LldbBreakpointHitEvent(debug_process_info)
```
Note that I've omitted the Java-style comments and license information, as they are not relevant to the translation. Also, in Python, we can simply define an `object` type for `DebugProcessInfo`, since it's just a simple data container.