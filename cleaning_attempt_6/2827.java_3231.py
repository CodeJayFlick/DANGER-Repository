from abc import ABCMeta, abstractmethod

class BoundedShape(metaclass=ABCMeta):
    @abstractmethod
    def get_bounds(self) -> 'BoundedShape':
        pass

    @abstractmethod
    def description(self) -> str:
        pass
