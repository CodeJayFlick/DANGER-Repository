class ZombieVillagerData:
    villager_support = Skript.is_running_minecraft(1, 11)
    profession_update = Skript.is_running_minecraft(1, 14)

    professions = [p for p in Villager.Profession]

    def __init__(self):
        pass

    def __init__(self, prof):
        self.profession = prof
        super().matched_pattern = prof.ordinal()

    @property
    def matched_pattern(self):
        return self.profession.ordinal()

    def init(self, exprs: list[Literal], matched_pattern: int, parse_result: ParseResult) -> bool:
        if matched_pattern < len(self.professions):
            self.profession = self.professions[matched_pattern]
        else:
            raise ValueError("Invalid profession")
        return True

    @property
    def type(self) -> Class[ZombieVillager]:
        return ZombieVillager

    def set(self, e: ZombieVillager) -> None:
        if isinstance(e, ZombieVillager):
            e.set_villager_profession(self.profession)
        else:
            raise ValueError("Invalid entity")

    @property
    def profession(self) -> Villager.Profession:
        return self._profession

    @professions.setter
    def professions(self, value: int) -> None:
        if isinstance(value, int):
            try:
                self._profession = self.professions[value]
            except IndexError as e:
                raise ValueError("Invalid profession") from e
        else:
            raise TypeError("Expected an integer")

    @property
    def is_supertype_of(self, other: EntityData) -> bool:
        if isinstance(other, ZombieVillagerData):
            return self.profession == other.profession
        return False

    @property
    def super_type(self) -> EntityData:
        return ZombieVillagerData(self.profession)

class SkriptAPIException(Exception):
    pass

class ParseResult:
    pass

class Literal:
    pass

from enum import Enum, auto

class VillagerProfession(Enum):
    NONE = 0
    NORMAL = auto()
    ARMORER = auto()
    BUTCHER = auto()
    CARTOGRAPHER = auto()
    CLERIC = auto()
    FARMER = auto()
    FISHERMAN = auto()
    FLINTLOCKSMITH = auto()
    LEATHERWORKER = auto()
    LIBRARIAN = auto()
    MASON = auto()
    NITWIT = auto()
    SHEPHERD = auto()

class ZombieVillager:
    def __init__(self):
        pass

    @property
    def villager_profession(self) -> VillagerProfession:
        return self._villager_profession

    @villager_profession.setter
    def set_villager_profession(self, value: VillagerProfession) -> None:
        if isinstance(value, VillagerProfession):
            self._villager_profession = value
        else:
            raise TypeError("Expected a VillagerProfession")
