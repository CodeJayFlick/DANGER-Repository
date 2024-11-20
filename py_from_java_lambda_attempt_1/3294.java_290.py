Here's your Java code translated into equivalent Python:

```Python
class ProgramVisibilityChangePluginEvent:
    NAME = "Open/Close Program"
    TOOL_EVENT_NAME = "Open/Close Program"

    def __init__(self, source: str, program: object, is_visible: bool):
        self.source = source
        self.name = self.NAME
        self.is_visible = is_visible
        if isinstance(program, type(None)):
            self.program_ref = None
        else:
            import weakref
            self.program_ref = weakref.ref(program)

    def get_program(self) -> object:
        return self.program_ref()

    def is_program_visible(self):
        return self.is_visible


# Usage example:

class ProgramVisibilityChangePluginEventPython(ProgramVisibilityChangePluginEvent):

    pass

event = ProgramVisibilityChangePluginEvent("source", "program", True)
print(event.get_program())
print(event.is_program_visible())

```

Note that Python does not have direct equivalent of Java's `@ToolEventName` annotation. In the above code, I've simply removed this part as it is specific to Java and doesn't translate well into Python.

Also note that in Python, we don't need explicit type declarations like `public`, `private`, etc., which are used for encapsulation in Java.