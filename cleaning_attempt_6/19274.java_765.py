from abc import ABCMeta, abstractmethod

class IsTameable:
    def __init__(self):
        pass

    @property
    def description(self):
        return "Check if an entity is tameable."

    @property
    def examples(self):
        return ["on damage:",
                "\tif victim is tameable:",
                "\t\tcancel event"]

    @property
    def since(self):
        return "2.5"

    @staticmethod
    def register():
        pass

    def check(self, entity: 'LivingEntity') -> bool:
        if isinstance(entity, Tameable):
            return True
        else:
            return False


class LivingEntity(metaclass=ABCMeta):
    @abstractmethod
    def is_tameable(self) -> bool:
        pass


class Tameable(LivingEntity):
    def __init__(self):
        super().__init__()

    def is_tameable(self) -> bool:
        return True

