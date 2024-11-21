class CreeperData:
    def __init__(self):
        self.registered = False
        self.powered = 0

    @classmethod
    def register(cls):
        EntityData.register(CreeperData, "creeper", Creeper, 1, "unpowered creeper", "creeper", "powered creeper")
        cls.registered = True

    def init(self, exprs: list[Literal], matched_pattern: int, parse_result: ParseResult) -> bool:
        self.powered = matched_pattern - 1
        return True

    def init(self, c: Class[Creeper] | None, e: Creeper | None) -> bool:
        if e is None:
            self.powered = 0
        else:
            self.powered = 1 if e.isPowered() else -1
        return True

    def set(self, creeper: Creeper):
        if self.powered != 0:
            creeper.setPowered(self.powered == 1)

    def match(self, entity: Creeper) -> bool:
        return self.powered == 0 or (entity.isPowered() and self.powered == 1)

    @classmethod
    def get_type(cls):
        return Creeper

    def __hash__(self):
        return hash(self.powered)

    def __eq__(self, other: EntityData) -> bool:
        if not isinstance(other, CreeperData):
            return False
        return self.powered == other.powered

    @classmethod
    def deserialize(cls, s: str) -> bool:
        try:
            cls.powered = int(s)
            return True
        except ValueError:
            return False

    def is_supertype_of(self, e: EntityData) -> bool:
        if isinstance(e, CreeperData):
            return self.powered == 0 or (e.powered and self.powered == e.powered)
        return False

    @classmethod
    def get_super_type(cls):
        return cls()
