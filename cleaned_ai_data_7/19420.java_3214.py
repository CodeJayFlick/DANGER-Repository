class PigData:
    def __init__(self):
        self.saddled = 0

    @staticmethod
    def register():
        EntityData.register(PigData, "pig", Pig, 1, "unsaddled pig", "pig", "saddled pig")

    def init(self, exprs: list[Literal], matched_pattern: int, parse_result: ParseResult) -> bool:
        self.saddled = matched_pattern - 1
        return True

    def init(self, c: Class[Pig] | None, e: Pig | None) -> bool:
        if e is None:
            self.saddled = 0
        elif e.has_saddle():
            self.saddled = 1
        else:
            self.saddled = -1
        return True

    def deserialize(self, s: str) -> bool:
        try:
            self.saddled = int(s)
            return abs(self.saddled) <= 1
        except ValueError:
            return False

    def set(self, entity: Pig):
        if self.saddled != 0:
            entity.set_saddle(self.saddled == 1)

    def match(self, entity: Pig) -> bool:
        return self.saddled == 0 or entity.has_saddle() == (self.saddled == 1)

    @property
    def type(self):
        return Pig

    def equals_i(self, obj: EntityData | None) -> bool:
        if not isinstance(obj, PigData):
            return False
        other = obj
        return self.saddled == other.saddled

    def hash_code_i(self) -> int:
        return self.saddled

    def is_supertype_of(self, e: EntityData | None) -> bool:
        if not isinstance(e, PigData):
            return False
        other = e
        return self.saddled == 0 or self.saddled == other.saddled

    @property
    def super_type(self):
        return PigData()
