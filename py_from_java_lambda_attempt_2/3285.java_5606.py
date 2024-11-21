Here is the translation of the given Java code into Python:

```Python
class ExternalProgramSelectionPluginEvent:
    NAME = "ExternalProgramSelection"
    TOOL_EVENT_NAME = "Program Selection"

    def __init__(self, src: str, selection: 'ProgramSelection', program: 'Program'):
        super().__init__(src, self.NAME)
        self.selection = selection
        self.program_ref = weakref.ref(program)

    @property
    def selection(self):
        return self._selection

    @selection.setter
    def selection(self, value):
        self._selection = value

    @property
    def program(self) -> 'Program':
        return self.program_ref()

class ProgramSelection:
    pass

class Program:
    pass
```

Please note that Python does not have direct equivalent of Java's `@ToolEventName` annotation. In the given code, I used a class attribute to represent this concept.

Also, in Python, we don't need to explicitly define getter and setter methods for attributes like we do in Java. This is because Python has built-in support for property-based access control through its `property()` function.