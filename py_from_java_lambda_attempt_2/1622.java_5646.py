Here is the translation of the given Java code into equivalent Python:

```Python
class LldbThreadResumedEvent:
    def __init__(self, info):
        pass  # No direct equivalent in Python for super() call


# Assuming DebugThreadInfo class exists elsewhere in your program or library
from . import DebugThreadInfo

class AbstractLldbEvent(DebugThreadInfo):  # Note: This is not a perfect translation as it's missing the abstract keyword and some Java-specific features.
    def __init__(self, info):
        self.info = info


# Usage:
event = LldbThreadResumedEvent(some_DebugThreadInfo_instance)
```

Please note that Python does not have direct equivalents for many of the Java constructs like `public`, `class`, `extends`, etc. Also, Python's class system is more flexible and less rigid than Java's.