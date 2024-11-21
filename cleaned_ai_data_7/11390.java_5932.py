class StartInstructionValueSolver:
    def __init__(self):
        pass

    def solve(self, iv: 'StartInstructionValue', goal: int, vals: dict, res: dict, cur: any, hints: set, description: str) -> tuple:
        raise AssertionError("INTERNAL: Should never be asked to solve for " + AssemblyTreeResolver.INST_START)

    def get_value(self, iv: 'StartInstructionValue', vals: dict, res: dict, cur: any) -> int:
        return vals.get(AssemblyTreeResolver.INST_START)

    def get_instruction_length(self, exp: 'StartInstructionValue', res: dict) -> int:
        return 0

    def value_for_resolution(self, exp: 'StartInstructionValue', rc: any) -> tuple:
        raise UnsupportedOperationException("The solver should never ask for this value given a resolved constructor.")
