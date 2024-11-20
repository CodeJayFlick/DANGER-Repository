Here is the translation of the given Java interface into a Python class:

```Python
class GraphDisplay:
    ALIGN_LEFT = 0
    ALIGN_CENTER = 1
    ALIGN_RIGHT = 2

    SELECTED_VERTEX_COLOR = "selectedVertexColor"
    SELECTED_EDGE_COLOR = "selectedEdgeColor"
    INITIAL_LAYOUT_ALGORITHM = "initialLayoutAlgorithm"
    DISPLAY_VERTICES_AS_ICONS = True
    VERTEX_LABEL_POSITION = ["N", "NE", "E", "SE", "S", "SW", "W", "NW", "AUTO", "CNTR"]
    ENABLE_EDGE_SELECTION = False
    EDGE_TYPE_PRIORITY_LIST = []
    FAVORED_EDGES = []

    def __init__(self):
        self.graph_display_listener = None

    def set_graph_display_listener(self, listener):
        self.graph_display_listener = listener

    def set_focused_vertex(self, vertex: 'AttributedVertex', event_trigger=None) -> None:
        pass  # implement this method in your subclass

    @property
    def graph(self) -> 'AttributedGraph':
        return None

    @graph.setter
    def graph(self, value):
        self._graph = value

    @property
    def focused_vertex(self) -> 'AttributedVertex' | None:
        return None

    def select_vertices(self, vertex_set: set['AttributedVertex'], event_trigger=None) -> None:
        pass  # implement this method in your subclass

    @property
    def selected_vertices(self) -> set['AttributedVertex']:
        return set()

    def close(self):
        pass  # implement this method in your subclass

    def set_graph(self, graph: 'AttributedGraph', options=None, title="", append=False, monitor=None) -> None:
        if not options:
            options = GraphDisplayOptions(graph.get_graph_type())
        self.graph = graph
        self._graph_title = title
        self._append = append
        self._monitor = monitor

    def clear(self):
        pass  # implement this method in your subclass

    def update_vertex_name(self, vertex: 'AttributedVertex', new_name) -> None:
        pass  # implement this method in your subclass

    @property
    def graph_title(self) -> str | None:
        return self._graph_title

    def add_action(self, action):
        if not hasattr(self, "_actions"):
            self._actions = []
        self._actions.append(action)

class AttributedVertex:
    pass  # implement this class in your subclass

class AttributedGraph:
    pass  # implement this class in your subclass

class GraphDisplayOptions:
    def __init__(self, graph_type):
        self.graph_type = graph_type
```

Note that the Java interface is translated into a Python class with similar methods and properties. The `AttributedVertex`, `AttributedGraph` classes are also defined as abstract base classes in this translation.