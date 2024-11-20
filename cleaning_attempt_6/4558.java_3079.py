class ProgramLocationPair:
    def __init__(self, program: 'Program', location: 'ProgramLocation'):
        if not isinstance(program, Program):
            raise TypeError("Program cannot be null")
        if not isinstance(location, ProgramLocation):
            raise TypeError("ProgramLocation cannot be null")

        self.program = program
        self.location = location

    @property
    def program(self) -> 'Program':
        return self._program

    @property
    def location(self) -> 'ProgramLocation':
        return self._location


class Program:
    pass


class ProgramLocation:
    pass
