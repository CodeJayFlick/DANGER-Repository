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

