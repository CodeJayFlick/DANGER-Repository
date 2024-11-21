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
