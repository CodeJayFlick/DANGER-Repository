Here is the translation of the given Java code into Python:

```Python
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
```

Please note that Python does not have direct equivalent of Java's MaskedLong class. I replaced it with simple integers for demonstration purposes. Also, the compute_right method in the original code seems to be designed to handle a list of values and goals which is not handled here as it was unclear from the given information how this should work.