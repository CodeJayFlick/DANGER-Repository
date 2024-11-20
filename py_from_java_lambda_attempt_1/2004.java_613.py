Here's your Java enum translated into a Python class:

```Python
class JdiBreakpointType:
    BREAKPOINT = ("breakpoint", False)
    ACCESS_WATCHPOINT = ("access watchpont", True)
    MODIFICATION_WATCHPOINT = ("modification watchpont", True)
    OTHER = ("<OTHER>", False)

    BY_NAME = {name: value for name, _ in JdiBreakpointType.__dict__.values()}

    @classmethod
    def from_str(cls, string):
        return JdiBreakpointType.BY_NAME.get(string, cls.OTHER)

    def __init__(self, name, is_watchpoint):
        self.name = name
        self.is_watchpoint = is_watchpoint

    def __str__(self):
        return self.name

    @property
    def name(self):
        return self.name

    @property
    def is_watchpoint(self):
        return self.is_watchpoint
```

This Python class `JdiBreakpointType` has the same functionality as your Java enum. It uses a dictionary (`BY_NAME`) to map names of breakpoint types to their corresponding instances, and it provides methods for parsing strings into breakpoint type objects and accessing the name and watchpoint status of each breakpoint type.