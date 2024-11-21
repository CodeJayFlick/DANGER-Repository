class InstructionDecodeException(Exception):
    def __init__(self, reason: str, program_counter: int) -> None:
        super().__init__(f"Instruction decode failed ({reason}), PC={program_counter}")
        self.program_counter = program_counter
