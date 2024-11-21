class ContextFieldSolver:
    def __init__(self):
        pass

    def solve(self, cf: 'ContextField', goal: int, vals: dict, res: dict, cur: object, hints: set, description: str) -> tuple:
        assert cf.min_value == 0  # In case someone decides to do signedness there.
        if not self.is_valid_goal(cf.max_value, cf.has_signbit(), goal):
            return "Value {} is not valid for {}".format(goal, cf), None
        block = AssemblyPatternBlock.from_context_field(cf, goal)
        return "Context only: {}".format(block), description

    def get_instruction_length(self, cf: 'ContextField', res: dict) -> int:
        return 0  # this is a context field, not an instruction (token) field

    @staticmethod
    def value_for_resolution(cf: 'ContextField', rc: object) -> tuple:
        size = cf.byte_end - cf.byte_start + 1
        res = rc.read_context(cf.byte_start, size)
        res = res >> cf.shift()
        if cf.has_signbit():
            res = res.sign_extend(cf.end_bit - cf.start_bit + 1)
        else:
            res = res.zero_extend(cf.end_bit - cf.start_bit + 1)
        return res

    @staticmethod
    def is_valid_goal(max_value: int, has_signbit: bool, goal: int) -> bool:
        if not (0 <= goal < max_value):
            return False
        if has_signbit and ((goal >> (max_value.bit_length() - 1)) != 0):
            return False
        return True

class AssemblyPatternBlock:
    @staticmethod
    def from_context_field(cf: 'ContextField', goal: int) -> str:
        pass

# Usage example:

cf = ContextField()
rc = AssemblyResolvedConstructor()

solver = ContextFieldSolver()
result, description = solver.solve(cf, 10, {}, {}, rc, set(), "Description")
print(result)
