class SubExpressionSolver:
    def __init__(self):
        pass

    def compute_left(self, lval: int, goal: int) -> int:
        return lval + goal

    def compute_right(self, rvals: list[int], goals: list[int]) -> None:
        for i in range(len(rvals)):
            print(f"rval {i} - goal {goals[i]} = {rvals[i] - goals[i]}")

    def solve_expression(self, lval: int, rval: int) -> int:
        return lval - rval

# Example usage
solver = SubExpressionSolver()
lval = 10
goal = 5
print(f"Left computation: {solver.compute_left(lval, goal)}")
rvals = [2, 3]
goals = [1, 4]
for i in range(len(rvals)):
    print(f"Right computation: {i} - {goals[i]} = {solver.solve_expression(rvals[i], goals[i])}")
