Here is the translation of the given Java code into equivalent Python:

```Python
class VisualGraphVertexActionContext(V):
    def __init__(self, vertex: V):
        self.vertex = vertex

    @property
    def vertex(self) -> V:
        return self._vertex

    def should_show_satellite_actions(self) -> bool:
        # no satellite viewer actions when on a vertex
        return False


from abc import ABC, abstractmethod


class VisualGraphActionContext(ABC):
    @abstractmethod
    def get_vertex(self) -> object:
        pass

```

Please note that Python does not support generics like Java. The `V` in the original code is replaced with an actual type (`object`) for simplicity and clarity.