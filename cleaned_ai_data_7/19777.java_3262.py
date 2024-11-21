from abc import ABC, abstractmethod

class DefaultExpression(ABC):
    @abstractmethod
    def init(self) -> bool:
        pass

    @property
    @abstractmethod
    def is_default(self) -> bool:
        pass
