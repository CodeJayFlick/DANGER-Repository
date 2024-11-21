class GoatData:
    def __init__(self):
        pass

    @classmethod
    def register(cls):
        if hasattr(Skript, 'Goat'):
            EntityData.register(cls, "goat", Goat, 0,
                                "goat", "screaming goat", "quiet goat")

    def __init__(self, screaming=0):  # default value is 0
        self.screaming = screaming

    def init(self, exprs=None, matched_pattern=-1):
        if matched_pattern > -1:
            self.screaming = matched_pattern
        return True

    def set_entity(self, entity: Goat):
        if self.matched_pattern > -1 and self.screaming == 1:
            entity.set_screaming(True)
        elif self.matched_pattern > -1 and self.screaming == 2:
            entity.set_screaming(False)

    def match(self, entity: Goat) -> bool:
        if self.matched_pattern > -1:
            return (entity.is_screaming() and self.screaming == 1) or \
                   (not entity.is_screaming() and self.screaming == 2)
        return True

    @property
    def type(self):
        return Goat

    def get_super_type(self):
        return GoatData(self.screaming)

    def __hash__(self):
        return hash(self.screaming)

    def __eq__(self, other: 'GoatData') -> bool:
        if not isinstance(other, GoatData):
            return False
        return self.screaming == other.screaming

    def is_supertype_of(self, data: EntityData) -> bool:
        if not isinstance(data, GoatData):
            return False
        return self.screaming == data.screaming


class Skript:
    @classmethod
    def has_class(cls, name):
        return hasattr(cls, name)

class Goat:
    def set_screaming(self, screaming: bool):
        pass

    def is_screaming(self) -> bool:
        pass

class EntityData:
    @classmethod
    def register(cls, data_type, pattern_name, entity_type, priority=0,
                 description=None, *args):
        pass

    @property
    def matched_pattern(self):
        return -1  # default value is -1

    def set_screaming(self, screaming: bool):
        pass

    def is_screaming(self) -> bool:
        pass


class Literal:
    pass

class ParseResult:
    pass

from typing import ClassVar
