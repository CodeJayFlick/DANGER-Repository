class VariableXRefLocationDescriptor:
    def __init__(self, program_location: 'ProgramLocation', program: 'Program'):
        super().__init__(program_location, program)

    def validate(self):
        if self.program_location is None:
            raise ValueError("Cannot create a LocationDescriptor from a null ProgramLocation")
        
        if not isinstance(self.program_location, VariableXRefFieldLocation):
            raise AssertionError(f"Unexpected ProgramLocation type - Cannot create a LocationDescriptor for type: {self.program_location}")

    def get_xref_address(self) -> 'Address':
        return (self.program_location).get_ref_address()
