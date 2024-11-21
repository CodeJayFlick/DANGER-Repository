Here is the translation of the Java code to Python:
```
class DbgBreakpointCreatedEvent:
    def __init__(self, info):
        self._bkpt_info = info

    @property
    def breakpoint_info(self):
        return self._bkpt_info


from typing import Any

class AbstractDbgEvent(T):  # Note: This is not a built-in Python class. You would need to define it.
    pass
```
Note that I've made the following changes:

* Renamed `package` and `public` keywords, which are specific to Java, to nothing (since they're not needed in Python).
* Replaced `extends AbstractDbgEvent<DbgBreakpointInfo>` with a simple class definition.
* Changed `private final` fields to instance variables (`self._bkpt_info`) since there's no equivalent concept of "final" or "private" in Python.
* Implemented the `getBreakpointInfo()` method as a property (using the `@property` decorator) instead of a separate function.