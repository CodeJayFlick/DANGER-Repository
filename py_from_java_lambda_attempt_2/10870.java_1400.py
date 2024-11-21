Here is the translation of the given Java interface into a Python class:

```Python
from abc import ABC, abstractmethod

class VisualGraph(ABC):
    @abstractmethod
    def vertex_location_changed(self, v: 'VisualVertex', point: tuple, change_type: str) -> None:
        pass

    @property
    @abstractmethod
    def focused_vertex(self) -> 'VisualVertex':
        pass

    @focused_vertex.setter
    @abstractmethod
    def focused_vertex(self, v: 'VisualVertex') -> None:
        pass

    @abstractmethod
    def clear_selected_vertices(self) -> None:
        pass

    @abstractmethod
    def set_selected_vertices(self, vertices: set['VisualVertex']) -> None:
        pass

    @property
    @abstractmethod
    def selected_vertices(self) -> set['VisualVertex']:
        pass

    @abstractmethod
    def add_graph_change_listener(self, listener: 'VisualGraphChangeListener') -> None:
        pass

    @abstractmethod
    def remove_graph_change_listener(self, listener: 'VisualGraphChangeListener') -> None:
        pass

    @property
    @abstractmethod
    def layout(self) -> 'VisualGraphLayout':
        pass

    @abstractmethod
    def copy(self) -> 'VisualGraph':
        pass


class VisualVertex:
    # Add your implementation here
    pass


class VisualEdge(VisualVertex):
    # Add your implementation here
    pass


class VisualGraphChangeListener:
    # Add your implementation here
    pass


class VisualGraphLayout:
    # Add your implementation here
    pass

```

Please note that the above Python code is a direct translation of the given Java interface and does not include any actual implementations. The `VisualVertex`, `VisualEdge`, `VisualGraphChangeListener` classes, and the `VisualGraphLayout` class are placeholders for actual implementations in Python.