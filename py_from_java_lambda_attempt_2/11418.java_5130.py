Here is the translation of the given Java code into equivalent Python:

```Python
class AssemblyResolvedBackfill:
    def __init__(self, description: str, exp, goal, res, inslen: int, offset: int):
        self.exp = exp
        self.goal = goal
        self.res = res
        self.inslen = inslen
        self.offset = offset

    @property
    def compute_hash(self) -> int:
        result = 0
        result += hash(self.exp)
        result *= 31
        result += hash(self.goal)
        result *= 31
        result += self.inslen
        result *= 31
        result += self.offset
        return result

    @property
    def get_instruction_length(self) -> int:
        return self.offset + self.inslen

    @property
    def is_error(self) -> bool:
        return False

    @property
    def is_backfill(self) -> bool:
        return True

    @property
    def line_to_string(self) -> str:
        return f"Backfill (len: {self.inslen}, off: {self.offset}) {self.goal} := {self.exp} ({self.description})"

    def copy(self):
        cp = AssemblyResolvedBackfill(description=self.description, exp=self.exp, goal=self.goal, res=self.res,
                                      inslen=self.inslen, offset=self.offset)
        return cp

    def shift(self, amt: int) -> 'AssemblyResolvedBackfill':
        return AssemblyResolvedBackfill(description=self.description, exp=self.exp, goal=self.goal, res=self.res,
                                        inslen=self.inslen, offset=self.offset + amt)

    @property
    def description(self):
        pass  # This is not implemented in the original Java code

    def solve(self, solver: 'RecursiveDescentSolver', vals: dict, cur: 'AssemblyResolvedConstructor') -> 'AssemblyResolution':
        try:
            ar = solver.solve(exp=self.exp, goal=self.goal, vals=vals, res=self.res,
                               truncate_offset=cur.truncate(self.offset), description=self.description)
            if isinstance(ar, AssemblyResolution):
                return ar.shift(self.offset)  # This is not implemented in the original Java code
        except NeedsBackfillException:
            return AssemblyResolution.error("Solution still requires backfill", self.description, None)
        except UnsupportedOperationException as e:
            return AssemblyResolution.error(f"Unsupported: {e.message}", self.description, None)

class RecursiveDescentSolver:
    pass  # This is not implemented in the original Java code

class AssemblyResolvedConstructor:
    def truncate(self, offset):
        pass  # This is not implemented in the original Java code

class PatternExpression:
    @property
    def hash_code(self) -> int:
        return hash(self)

class MaskedLong:
    @property
    def hash_code(self) -> int:
        return hash(self)
```

Note that I've used Python's type hinting system to indicate the expected types of method parameters and return values.