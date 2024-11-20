class AssemblyResolution:
    def __init__(self, description: str, children: list):
        self.description = description
        self.children = children if children else []

    @property
    def hashed(self) -> bool:
        return False

    @hashed.setter
    def hashed(self, value: bool):
        self._hashed = value

    @property
    def hash(self) -> int:
        return 0

    @hash.setter
    def hash(self, value: int):
        self._hash = value

    def __eq__(self, other):
        if not isinstance(other, AssemblyResolution):
            return False
        return self.description == other.description and self.children == other.children

    def compute_hash(self) -> int:
        pass  # abstract method

    @property
    def description(self) -> str:
        return self._description

    @description.setter
    def description(self, value: str):
        self._description = value

    @property
    def children(self) -> list:
        return self._children

    @children.setter
    def children(self, value: list):
        if not isinstance(value, list):
            raise TypeError("Children must be a list")
        self._children = value


class AssemblyResolvedConstructor(AssemblyResolution):
    def __init__(self, description: str, sel: list, ins: 'AssemblyPatternBlock', ctx: 'AssemblyPatternBlock',
                 min_len: int, max_len: int):
        super().__init__(description, sel)
        self.ins = ins
        self.ctx = ctx
        self.min_len = min_len
        self.max_len = max_len

    @staticmethod
    def resolved(ins: 'AssemblyPatternBlock', ctx: 'AssemblyPatternBlock', description: str,
                 children: list) -> 'AssemblyResolvedConstructor':
        return AssemblyResolvedConstructor(description, children, ins, ctx, 0, 0)

    @staticmethod
    def instr_only(ins: 'AssemblyPatternBlock', description: str, children: list) -> 'AssemblyResolvedConstructor':
        return resolved(ins, AssemblyPatternBlock.nop(), description, children)

    @staticmethod
    def context_only(ctx: 'AssemblyPatternBlock', description: str, children: list) -> 'AssemblyResolvedConstructor':
        return resolved(AssemblyPatternBlock.nop(), ctx, description, children)


class AssemblyResolvedBackfill(AssemblyResolution):
    def __init__(self, description: str, exp: 'PatternExpression', goal: MaskedLong,
                 res: dict, ins_len: int, max_len: int):
        super().__init__(description, [])
        self.exp = exp
        self.goal = goal
        self.res = res
        self.ins_len = ins_len
        self.max_len = max_len

    @staticmethod
    def backfill(exp: 'PatternExpression', goal: MaskedLong, res: dict,
                 ins_len: int, description: str) -> 'AssemblyResolvedBackfill':
        return AssemblyResolvedBackfill(description, exp, goal, res, ins_len, 0)


class AssemblyResolvedError(AssemblyResolution):
    def __init__(self, error: str, description: str, children: list):
        super().__init__(description, children)
        self.error = error

    @staticmethod
    def error(error: str, description: str, children: list) -> 'AssemblyResolvedError':
        return AssemblyResolvedError(description, children, error)

    @staticmethod
    def from_pattern(res: 'AssemblyResolvedConstructor') -> 'AssemblyResolvedError':
        return error(res.description, res.children)
