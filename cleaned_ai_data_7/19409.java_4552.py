class FoxData:
    def __init__(self):
        pass

    @classmethod
    def register(cls):
        if hasattr(Skript, 'org_bukkit_entity_Fox'):
            EntityData.register(FoxData, "fox", Fox, 1,
                                 "fox", "red fox", "snow fox")

    def __init__(self, type=None):
        self.type = type
        super().matched_pattern = 2 if type == Type.SNOW else 1

    @property
    def matched_pattern(self):
        return self._matched_pattern

    @matched_pattern.setter
    def matched_pattern(self, value):
        self._matched_pattern = value

    def init(self, exprs: list[Literal], pattern: int, parse_result: ParseResult) -> bool:
        if pattern > 0:
            self.type = Type.values()[pattern - 1]
        return True

    def init(self, c: Class[Fox], fox: Fox) -> bool:
        if fox is not None:
            self.type = fox.get_fox_type()
        return True

    def set(self, entity: Fox):
        if self.type is not None:
            entity.set_fox_type(self.type)

    def match(self, entity: Fox) -> bool:
        return self.type is None or self.type == entity.get_fox_type()

    @property
    def type_class(self):
        return Fox

    def get_super_type(self) -> 'FoxData':
        if self.type is not None:
            return FoxData(self.type)
        else:
            return super().get_super_type()

    def __hash__(self) -> int:
        return hash(self.type)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, FoxData):
            return self.type == other.type
        return False

    def is_supertype_of(self, data: 'FoxData') -> bool:
        if not isinstance(data, FoxData):
            return False
        return self.type is None or self.type == data.type
