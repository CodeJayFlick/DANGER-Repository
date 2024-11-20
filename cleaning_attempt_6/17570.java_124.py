import io
from abc import ABC, abstractmethod


class LayerRowWindowReader(ABC):
    @abstractmethod
    def next(self) -> bool:
        pass

    @abstractmethod
    def ready_for_next(self) -> None:
        pass

    @property
    @abstractmethod
    def data_types(self) -> list[TSDataType]:
        pass

    @property
    @abstractmethod
    def current_window(self) -> RowWindow:
        pass


class TSDataType(ABC):
    @abstractmethod
    pass


# You would need to define the RowWindow class and its properties
