from abc import ABC, abstractmethod

class PropertyVisitor(ABC):
    @abstractmethod
    def visit_void(self): pass

    @abstractmethod
    def visit_string(self, value: str) -> None:
        ...

    @abstractmethod
    def visit_object(self, value: object) -> None:
        ...

    @abstractmethod
    def visit_saveable(self, value: 'Saveable') -> None:
        ...

    @abstractmethod
    def visit_int(self, value: int) -> None:
        ...
