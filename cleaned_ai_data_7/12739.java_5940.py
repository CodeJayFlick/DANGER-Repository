class AssignedVariableLocation:
    def __init__(self, program: 'Program', addr: int, row: int, char_offset: int):
        super().__init__(program, addr, row, 0, char_offset)

    @property
    def get_row(self) -> int:
        # implement this method if needed
        pass

class ProgramLocation:
    def __init__(self, program: 'Program', addr: int, row: int, col_start: int, char_offset: int):
        self.program = program
        self.addr = addr
        self.row = row
        self.col_start = col_start
        self.char_offset = char_offset

class Program:
    pass  # assume this class exists in the Python codebase

# Example usage:
program = Program()  # create an instance of the Program class
addr = 0x12345678  # example address value
row = 1  # example row value
char_offset = 2  # example character offset value
location = AssignedVariableLocation(program, addr, row, char_offset)
