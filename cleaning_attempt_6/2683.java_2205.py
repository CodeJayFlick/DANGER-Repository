from abc import ABC, abstractmethod

class ExpanderArrowExpansionListener(ABC):
    @abstractmethod
    def changing(self, expanding: bool) -> None:
        pass  # Nothing

    @abstractmethod
    def changed(self, expanded: bool) -> None:
        pass
