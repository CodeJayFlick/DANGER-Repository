class UnimplementedInstructionException(Exception):
    def __init__(self, address):
        super().__init__(f"Unimplemented instruction, PC={address}")
        self.address = address

    @property
    def get_instruction_address(self):
        return self.address
