class XorExpressionSolver:
    def __init__(self):
        pass

    def compute_left(self, other: int, goal: int) -> int:
        return goal ^ other

    def compute(self, lval: int, rval: int) -> int:
        return lval ^ rval
