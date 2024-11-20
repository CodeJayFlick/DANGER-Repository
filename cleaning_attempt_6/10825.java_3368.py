from abc import ABCMeta, abstractmethod
import weakref
import itertools

class VisualVertex:
    pass

class VisualEdge:
    def __init__(self, vertex):
        self.vertex = vertex

class ArticulatedEdgeTransformer:
    pass

class ArticulatedEdgeRenderer:
    pass

class LayoutPositions:
    @staticmethod
    def create_new_positions(vertex_locations, edge_erticulations):
        return {'vertex_locations': vertex_locations, 'edge_erticulations': edge_erticulations}

class JungWrappingVisualGraphLayoutAdapter(metaclass=ABCMeta):

    def __init__(self, jung_layout):
        self.delegate = jung_layout
        self.edge_shape_transformer = ArticulatedEdgeTransformer()
        self.edge_renderer = ArticulatedEdgeRenderer()

    @abstractmethod
    def initialize(self):
        pass

    @abstractmethod
    def reset(self):
        pass

    def calculate_locations(self, graph, monitor=None):
        vertex_locations = {}
        vertices = list(graph.get_vertices())
        for v in vertices:
            location = self.delegate.apply(v)
            vertex_locations[v] = location

        edge_erticulations = {}
        edges = list(graph.get_edges())
        for e in edges:
            new_articulations = []
            edge_erticulations[e] = new_articulations

        return LayoutPositions.create_new_positions(vertex_locations, edge_erticulations)

    def clone_layout(self, graph):
        new_jung_layout = self.delegate.clone()
        return JungWrappingVisualGraphLayoutAdapter(new_jung_layout)

    @abstractmethod
    def uses_edge_articulations(self):
        pass

    def dispose(self):
        self.listeners.clear()

    @property
    def listeners(self):
        if not hasattr(self, '_listeners'):
            self._listeners = weakref.WeakKeyDictionary()
        return self._listeners

    @property
    def graph(self):
        return self.delegate.graph

    @graph.setter
    def graph(self, value):
        self.delegate.graph = value

    @abstractmethod
    def get_graph(self):
        pass

    @abstractmethod
    def get_size(self):
        pass

    @abstractmethod
    def is_locked(self, v):
        pass

    @abstractmethod
    def lock(self, v, lock):
        pass

    @property
    def edge_renderer(self):
        return self._edge_renderer

    @edge_renderer.setter
    def edge_renderer(self, value):
        self._edge_renderer = value

    @property
    def edge_shape_transformer(self):
        return self._edge_shape_transformer

    @edge_shape_transformer.setter
    def edge_shape_transformer(self, value):
        self._edge_shape_transformer = value

    @abstractmethod
    def apply(self, v):
        pass

    # Default Edge Stuff
    @property
    def default_edge_renderer(self):
        return self.edge_renderer

    @default_edge_renderer.getter
    def get_default_edge_renderer(self):
        return self.default_edge_renderer

    @default_edge_renderer.setter
    def set_default_edge_renderer(self, value):
        self.default_edge_renderer = value

    # Listener Stuff
    def add_layout_listener(self, listener):
        if not isinstance(listener, type) or issubclass(listener, LayoutListener):
            raise AssertionError("Cannot add anonymous listeners to a weak collection!")
        self.listeners[listener] = None

    def remove_layout_listener(self, listener):
        for reference in list(self.listeners.keys()):
            layout_listener = reference()
            if layout_listener == listener:
                del self.listeners[reference]
