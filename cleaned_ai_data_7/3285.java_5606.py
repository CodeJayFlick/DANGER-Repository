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
