class LeftShiftExpressionSolver:
    def __init__(self):
        pass

    def compute(self, lval: 'MaskedLong', rval: 'MaskedLong') -> 'MaskedLong':
        return lval.shift_left(rval)

    def compute_left(self, rval: 'MaskedLong', goal: 'MaskedLong') -> 'MaskedLong':
        try:
            return goal.inv_shift_left(rval)
        except SolverException as e:
            raise e

    def compute_right(self, lval: 'MaskedLong', goal: 'MaskedLong') -> 'MaskedLong':
        acc = 0
        bit = 1
        for i in range(64):
            if lval.shift_left(i).agrees(goal):
                acc |= bit
            bit <<= 1

        if Long.bit_count(acc) == 1:
            return MaskedLong.from_long(Long.numberOfTrailingZeros(acc))
        raise SolverException(f"Cannot solve for the left shift amount: {goal} = {lval} << L")

    def solve_two_sided(self, exp: 'LeftShiftExpression', goal: 'MaskedLong',
                         vals: dict[str, int], res: dict[int, object],
                         cur: 'AssemblyResolvedConstructor', hints: set['SolverHint'],
                         description: str) -> 'AssemblyResolution':
        if hints.contains(DefaultSolverHint.GUESSING_LEFT_SHIFT_AMOUNT):
            return super().solve_two_sided(exp, goal, vals, res, cur, hints, description)

        max_shift = Long.numberOfTrailingZeros(goal.val)
        hintsWithLShift = SolverHint.with(hints, DefaultSolverHint.GUESSING_LEFT_AMPOUNT)

        for shift in range(max_shift, -1, -1):
            try:
                reqr = MaskedLong.from_long(shift)
                reql = self.compute_left(reqr, goal)

                lres = solver.solve(exp.get_left(), reql, vals, res, cur, hintsWithLShift, description)
                if lres.is_error():
                    raise SolverException("Solving left failed")

                rres = solver.solve(exp.get_right(), reqr, vals, res, cur, hints, description)
                if rres.is_error():
                    raise SolverException("Solving right failed")

                lsol = AssemblyResolvedConstructor(lres)
                rsol = AssemblyResolvedConstructor(rres)
                sol = lsol.combine(rsol)

                return sol
            except (SolverException, UnsupportedOperationException) as e:
                Msg.trace(self, f"Shift of {shift} resulted in {e}")
        return super().solve_two_sided(exp, goal, vals, res, cur, hints, description)


class MaskedLong:
    @staticmethod
    def from_long(val: int):
        pass

    @staticmethod
    def shift_left(lval: 'MaskedLong', rval: 'MaskedLong') -> 'MaskedLong':
        pass

    @staticmethod
    def inv_shift_left(rval: 'MaskedLong') -> 'MaskedLong':
        pass


class SolverException(Exception):
    pass


class DefaultSolverHint:
    GUESSING_LEFT_SHIFT_AMOUNT = "GUESSING_LEFT_SHIFT_AMOUNT"


class AssemblyResolution:
    is_error(self) -> bool:
        pass

    def combine(self, other: 'AssemblyResolvedConstructor') -> 'AssemblyResolvedConstructor':
        pass
