class PrivateSaveable:
    def __init__(self):
        pass

    def is_private(self) -> bool:
        return True


from abc import ABC, abstractmethod


class Saveable(ABC):
    @abstractmethod
    def is_private(self) -> bool:
        pass
