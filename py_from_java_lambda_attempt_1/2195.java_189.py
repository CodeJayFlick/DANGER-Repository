Here is the translation of the given Java code into equivalent Python:

```Python
from concurrent.futures import Future

class TargetKillable:
    def __init__(self):
        pass

    def kill(self) -> Future[None]:
        # This function should return a future that completes when the target is successfully terminated.
        # For simplicity, let's assume it always succeeds and returns None.
        return Future(None)
```

Note: Python does not have direct equivalent of Java interfaces. However, we can achieve similar functionality using abstract classes or base classes with abstract methods in Python.

In this translation:

- The `@DebuggerTargetObjectIface("Killable")` annotation is removed as it's specific to the Ghidra framework and doesn't exist in standard Python.
- The `public interface TargetKillable extends TargetObject { ... }` declaration is replaced by a simple class definition (`class TargetKillable:`) without any inheritance or implementation of methods.