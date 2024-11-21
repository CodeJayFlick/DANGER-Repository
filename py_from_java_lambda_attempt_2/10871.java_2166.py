Here is the translation of the Java code into Python:

```Python
from abc import ABCMeta, abstractmethod
import typing as t

class VisualGraphComponentProvider(metaclass=ABCMeta):
    def __init__(self, tool: str, name: str, owner: str) -> None:
        self.sub_features = []

    @abstractmethod
    def get_view(self) -> 'VisualGraphView':
        pass

    def component_hidden(self) -> None:
        for f in self.sub_features:
            f.provider_closed(self)

    def component_shown(self) -> None:
        for f in self.sub_features:
            f.provider_opened(self)

    @property
    def is_satellite_showing(self) -> bool:
        graph_component = self.get_view().get_graph_component()
        return graph_component.is_satellite_showing()

    @property
    def is_satellite_docked(self) -> bool:
        return self.get_view().is_satellite_docked()

    def get_selected_vertices(self) -> t.Set['VisualVertex']:
        view = self.get_view()
        viewer = view.get_primary_graph_viewer()
        picked_state = viewer.get_picked_vertex_state()
        return picked_state.get_picked()

    @property
    def satellite_provider(self) -> 'ComponentProvider':
        feature = self.satellite_feature
        if feature is None:
            return None
        return feature.sattelite_provider

    @property
    def satellite_feature(self) -> t.Optional['VgSatelliteFeaturette']:
        for f in self.sub_features:
            if isinstance(f, VgSatelliteFeaturette):
                return f
        return None


class ComponentProvider(metaclass=ABCMeta):
    @abstractmethod
    def dispose(self) -> None:
        pass

    @abstractmethod
    def write_config_state(self, save_state: 'SaveState') -> None:
        pass

    @abstractmethod
    def read_config_state(self, save_state: 'SaveState') -> None:
        pass


class VgSatelliteFeaturette(metaclass=ABCMeta):
    def __init__(self) -> None:
        self.satellite_provider = None

    def init(self, provider: 'VisualGraphComponentProvider') -> None:
        pass

    @abstractmethod
    def write_config_state(self, save_state: 'SaveState') -> None:
        pass

    @abstractmethod
    def read_config_state(self, save_state: 'SaveState') -> None:
        pass


class VisualVertex(metaclass=ABCMeta):
    pass


class VisualEdge(metaclass=ABCMeta):
    pass


class VisualGraph(metaclass=ABCMeta):
    pass

```

Please note that this is a direct translation of the Java code into Python, and it may not be perfect. The equivalent classes in Python are `VisualGraphComponentProvider`, `VgSatelliteFeaturette`, `ComponentProvider` for Java's `VisualGraphComponentProvider`, `VgSatelliteFeaturette`, and `ComponentProvider`.