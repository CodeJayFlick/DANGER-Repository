class RecursiveDescentSolver:
    def __init__(self):
        self.registry = {}

    @staticmethod
    def get_solver():
        return _solver

    def register(self, tcls, s):
        self.registry[tcls] = s


_solver = RecursiveDescentSolver()

def solve(exp, goal, vals, res, cur, hints, description):
    try:
        solver_class = exp.__class__
        if solver_class in _solver.registry:
            return _solver.registry[solver_class].solve(exp, goal, vals, res, cur, hints, description)
        else:
            raise ValueError("No registered solver for class " + str(solver_class))
    except Exception as e:
        print(f"Error solving {exp} = {goal}")
        raise


def solve_expression(exp, goal, vals, res, cur, description):
    return solve(exp, goal, vals, res, cur, set(), description)


def get_value(exp, vals, res, cur):
    solver_class = exp.__class__
    if solver_class in _solver.registry:
        return _solver.registry[solver_class].get_value(exp, vals, res, cur)
    else:
        raise ValueError("No registered solver for class " + str(solver_class))


def get_instruction_length(exp, res):
    solver_class = exp.__class__
    if solver_class in _solver.registry:
        return _solver.registry[solver_class].get_instruction_length(exp, res)
    else:
        raise ValueError("No registered solver for class " + str(solver_class))


def value_for_resolution(exp, rc):
    solver_class = exp.__class__
    if solver_class in _solver.registry:
        return _solver.registry[solver_class].value_for_resolution(exp, rc)
    else:
        raise ValueError("No registered solver for class " + str(solver_class))
