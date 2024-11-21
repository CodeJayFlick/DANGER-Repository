Here is the translation of the given Java code into Python:

```Python
class AbstractExpressionSolver:
    def __init__(self, tcls):
        self.tcls = tcls
        self.solver = None
        self.dbg_timer = DbgTimer.INACTIVE  # Assuming a DbgTimer class exists in your environment

    @property
    def solver(self):
        return self._solver

    @solver.setter
    def solver(self, value):
        self._solver = value

    def solve(self, exp: 'T', goal: MaskedLong, vals: dict[str, int], res: dict[int, object],
              cur: AssemblyResolvedConstructor, hints: set[SolverHint], description: str) -> AssemblyResolution:
        raise NotImplementedError("Method must be implemented by subclass")

    def get_value(self, exp: 'T', vals: dict[str, int], res: dict[int, object], cur: AssemblyResolvedConstructor) -> MaskedLong | None:
        raise NotImplementedError("Method must be implemented by subclass")

    def get_instruction_length(self, exp: 'T', res: dict[int, object]) -> int:
        raise NotImplementedError("Method must be implemented by subclass")

    def value_for_resolution(self, exp: 'T', rc: AssemblyResolvedConstructor) -> MaskedLong | None:
        raise NotImplementedError("Method must be implemented by subclass")

    def register(self, general):
        self.solver = general
        general.register(self.tcls, self)
```

Please note that Python does not support generics like Java. The `T` type parameter in the original code is replaced with a string literal `'T'`.