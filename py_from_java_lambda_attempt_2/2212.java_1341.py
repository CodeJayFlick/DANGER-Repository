Here is the translation of the given Java code into equivalent Python:

```Python
from typing import Collection, List

class TargetStack:
    def __init__(self):
        pass

    @property
    def frames(self) -> 'Collection[TargetStackFrame]':
        # This method collects all successor frames ordered by path.
        return self._collect_frames()

    def _collect_frames(self) -> 'List[TargetStackFrame]':
        # Implement this method to collect the stack frames. For now, it returns an empty list.
        return []

class TargetStackFrame:
    pass

# This is not a real Python class but rather equivalent of DebuggerTargetObjectIface
class DebuggerTargetObjectInterface:
    def __init__(self):
        pass

@DebuggerTargetObjectInterface("Stack")
class TargetStack(TargetStack, DebuggerTargetObjectInterface):
    pass
```

Please note that this translation does not include the Java-specific features like annotations or interfaces. Python has different concepts and syntax for these things.