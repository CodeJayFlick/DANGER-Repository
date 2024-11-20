from abc import ABC, abstractmethod
import typing as t

class VisualGraphLayout(ABC):
    @abstractmethod
    def add_layout_listener(self, listener: 't.Callable[[object], None]') -> None:
        pass

    @abstractmethod
    def remove_layout_listener(self, listener: 't.Callable[[object], None]') -> None:
        pass

    @abstractmethod
    def uses_edge_articulations(self) -> bool:
        pass

    @abstractmethod
    def calculate_locations(
            self,
            graph: t.Any,
            monitor: t.Any
    ) -> t.Any:
        pass

    @abstractmethod
    def clone_layout(self, new_graph: t.Any) -> 'VisualGraphLayout':
        pass

    @abstractmethod
    def set_location(
            self,
            v: t.Any,
            location: tuple[float, float],
            change_type: str
    ) -> None:
        pass

    @property
    @abstractmethod
    def visual_graph(self) -> t.Any:
        pass

    @property
    @abstractmethod
    def edge_renderer(self) -> 't.Optional[t.Callable[[object], object]]':
        pass

    @property
    @abstractmethod
    def edge_shape_transformer(self) -> 't.Optional[t.Callable[[object], object]]':
        pass

    @property
    @abstractmethod
    def edge_label_renderer(self) -> 't.Optional[t.Callable[[object, object], None]]':
        pass

    @abstractmethod
    def dispose(self) -> None:
        pass


class LayoutPositions(t.Generic):
    # Define the class here if needed.
    pass
