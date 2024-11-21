class ProgramLocationPluginEvent:
    NAME = "ProgramLocationChange"

    def __init__(self, src: str, loc: 'ProgramLocation', program: 'Program'):
        super().__init__(src, self.NAME)
        
        if not isinstance(loc, object):
            raise TypeError("loc must be an instance of ProgramLocation")
            
        if not isinstance(program, object):
            raise TypeError("program must be an instance of Program")

        self.loc = loc
        self.program_ref = weakref.ref(program)

    def get_location(self) -> 'ProgramLocation':
        return self.loc

    def get_program(self) -> 'Program':
        return self.program_ref()

    def __str__(self):
        if self.loc:
            return f"{type(self.loc).__name__} addr==> {self.loc.get_address()}\n"
        else:
            return super().__str__()
