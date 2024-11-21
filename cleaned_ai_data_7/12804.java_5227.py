class ProgramLocation:
    def __init__(self, program: 'Program', addr: 'Address', byte_addr: 'Address',
                 component_path: list[int], ref_addr: 'Address' = None,
                 row: int = 0, col: int = 0, char_offset: int = 0):
        if not isinstance(program, Program) or not isinstance(addr, Address):
            raise TypeError("program and addr must be instances of Program and Address")
        self.program = program
        self.addr = addr
        self.byte_addr = byte_addr
        self.ref_addr = ref_addr
        self.component_path = component_path
        self.row = row
        self.col = col
        self.char_offset = char_offset

    def get_component_path(self) -> list[int]:
        return self.component_path

    def get_program(self) -> 'Program':
        return self.program

    def get_address(self) -> 'Address':
        return self.addr

    def get_byte_address(self) -> 'Address':
        return self.byte_addr

    def get_ref_address(self) -> 'Address' | None:
        return self.ref_addr

    @staticmethod
    def restore_state(program: 'Program', save_state):
        # Implementation of the Java method here...

    @staticmethod
    def get_location(program, save_state):
        # Implementation of the Java method here...
