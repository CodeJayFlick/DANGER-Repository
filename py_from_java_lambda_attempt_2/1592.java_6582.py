Here is the translation of the given Java code into equivalent Python:

```Python
class LldbBreakpointModifiedEvent:
    def __init__(self, breakpoint_info=None):
        self.id = None
        if breakpoint_info:
            super().__init__(breakpoint_info)
            self.id = DebugClient.get_id(breakpoint_info.pt)

    @classmethod
    def from_breakpoint_info(cls, breakpoint_info):
        return cls(breakpoint_info)

    @classmethod
    def from_id(cls, id):
        return cls(None)  # Initialize with None for getInfo() to work correctly

    def get_breakpoint_info(self):
        return self.get_info()

    def get_id(self):
        return self.id


class DebugBreakpointInfo:
    pass


class DebugClient:
    @staticmethod
    def get_id(pt):
        raise NotImplementedError("Method not implemented")
```

Note that the `DebugBreakpointInfo` and `DebugClient` classes are just placeholders, as they were abstract in Java. In Python, you would need to implement these classes or use existing ones depending on your specific requirements.

Also note that I did not include any type hints for variables like `id`, since Python does not have a built-in equivalent of Java's generics system.