class ImpliedMatchProgramCorrelator:
    MANUAL_SCORE = 1.0
    NAME = "Implied Match"

    def __init__(self, source_program: 'Program', destination_program: 'Program'):
        super().__init__(None, source_program, source_program.memory(), 
                         destination_program, destination_program.memory(),
                         {'name': self.NAME})

    @property
    def name(self):
        return self.NAME

class Program:
    pass

class VTMatchSet:
    pass

class VTScore:
    def __init__(self, score: float):
        self.score = score

class ToolOptions:
    def __init__(self, name: str):
        self.name = name
