from abc import ABC, abstractmethod

class ProjectDataColumn(ABC):
    def __init__(self):
        pass

    @abstractmethod
    def is_default_column(self) -> bool:
        pass

    @abstractmethod
    def get_priority(self) -> int:
        pass

    def compare_to(self, other: 'ProjectDataColumn') -> int:
        return self.get_priority() - other.get_priority()
