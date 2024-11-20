class CodeUnitLocation:
    def __init__(self, program: 'Program', addr: int, component_path=None, row=0, col=0, char_offset=0):
        super().__init__(program, addr, component_path, None, row, col, char_offset)

    @classmethod
    def from_program_addr(cls, program: 'Program', addr: int, byte_addr: int = 0, component_path=None, row=0, col=0, char_offset=0):
        return cls(program, addr, [byte_addr], component_path, row, col, char_offset)

    @classmethod
    def from_program(cls, program: 'Program', addr: int, row=0, col=0, char_offset=0):
        return cls(program, addr, None, 0, row, col, char_offset)

    def __init__(self):
        super().__init__()

    def is_valid(self, p) -> bool:
        if not super().is_valid(p):
            return False
        code_unit = p.get_listing().get_code_unit_containing(addr)
        return code_unit is not None

class Program:
    pass

class Address:
    pass

class Listing:
    def get_code_unit_containing(self, addr) -> 'CodeUnit':
        pass

class CodeUnit:
    pass
