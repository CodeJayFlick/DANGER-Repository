Here is the translation of the given Java code into Python:

```Python
class ExternalProgramLocationPluginEvent:
    NAME = "External Program Location Change"
    TOOL_EVENT_NAME = "Program Location Change"

    def __init__(self, src: str, loc: 'ProgramLocation', program: 'Program'):
        super().__init__(src, self.NAME)
        self.loc = loc
        self.program_ref = weakref.ref(program)

    @property
    def location(self):
        return self.loc

    @property
    def program(self):
        return self.program_ref()

class Program:
    pass

class ProgramLocation:
    pass
```

Please note that Python does not have direct equivalent of Java's `@ToolEventName` annotation. In the given code, I've used a property (`TOOL_EVENT_NAME`) to store this information.

Also, in Python, we don't need to specify types for method parameters like we do in Java. The type hinting is just an optional feature that can be used by tools and other developers to understand what kind of data the function expects or returns.