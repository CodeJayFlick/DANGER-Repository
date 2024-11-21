class EndInstructionValueSolver:
    def __init__(self):
        pass

    def solve(self, iv: 'EndInstructionValue', goal: int, vals: dict, res: dict,
              cur: object, hints: set, description: str) -> None:
        raise AssertionError("INTERNAL: Should never be asked to solve for " + AssemblyTreeResolver.INST_NEXT)

    def get_value(self, iv: 'EndInstructionValue', vals: dict, res: dict, cur: object) -> int:
        inst_next = vals.get(AssemblyTreeResolver.INST_NEXT)
        if inst_next is None:
            raise NeedsBackfillException(AssemblyTreeResolver.INST_NEXT)
        return inst_next

    def get_instruction_length(self, iv: 'EndInstructionValue', res: dict) -> int:
        return 0

    def value_for_resolution(self, exp: 'EndInstructionValue', rc: object) -> None:
        raise UnsupportedOperationException("The solver should never ask for this value given a resolved constructor.")
