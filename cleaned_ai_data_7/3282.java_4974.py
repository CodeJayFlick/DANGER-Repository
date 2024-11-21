class CloseProgramPluginEvent:
    NAME = "Close Program"

    def __init__(self, source: str, program: object, ignore_changes: bool):
        self.source = source
        self.name = self.NAME
        self.program_ref = weakref.ref(program)
        self.ignore_changes = ignore_changes

    @property
    def program(self) -> object:
        return self.program_ref()

    @property
    def ignores_changes(self) -> bool:
        return self.ignore_changes


class PluginEvent:
    pass


# Note: Python does not have a direct equivalent to Java's ToolEventName. This is because the concept of events and event handling in Python is different from that in Java.
