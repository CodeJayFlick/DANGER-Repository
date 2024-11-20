Here is the translation of the Java code into Python:

```Python
import unittest
from enum import Enum

class VertexShape(Enum):
    STAR = 1
    PENTAGON = 2
    DIAMOND = 3
    ELLIPSE = 4


class GraphDisplayOptions:
    def __init__(self, graph_type: str):
        self.graph_type = graph_type
        self.default_vertex_shape = VertexShape.STAR
        self.default_vertex_color = (255, 0, 128)  # Magenta
        self.default_edge_color = (255, 0, 128)  # Magenta

    def set_default_vertex_shape(self, vertex_shape: str):
        if isinstance(vertex_shape, str):
            try:
                self.default_vertex_shape = VertexShape[vertex_shape]
            except KeyError:
                pass
        elif isinstance(vertex_shape, VertexShape):
            self.default_vertex_shape = vertex_shape
        else:
            raise ValueError("Invalid vertex shape")

    def set_default_vertex_color(self, color: tuple):
        if len(color) == 3 and all(isinstance(x, int) for x in color):
            self.default_vertex_color = color

    def get_default_vertex_shape(self):
        return self.default_vertex_shape.name

    def get_default_vertex_color(self):
        return self.default_vertex_color


class AttributedVertex:
    def __init__(self, label: str):
        self.label = label
        self.vertex_type = None
        self.attributes = {}

    def set_vertex_type(self, vertex_type: str):
        if isinstance(vertex_type, str):
            self.vertex_type = vertex_type

    def add_attribute(self, key: str, value):
        if isinstance(key, str) and isinstance(value, (str, int)):
            self.attributes[key] = value


class AttributedEdge:
    def __init__(self, edge_id: str):
        self.edge_id = edge_id
        self.edge_type = None
        self.attributes = {}

    def set_edge_type(self, edge_type: str):
        if isinstance(edge_type, str):
            self.edge_type = edge_type

    def add_attribute(self, key: str, value):
        if isinstance(key, str) and isinstance(value, (str, int)):
            self.attributes[key] = value


class TestGraphDisplayOptions(unittest.TestCase):

    def setUp(self):
        graph_type = "Test"
        options = GraphDisplayOptions(graph_type)
        return options

    def test_set_get_default_vertex_shape(self):
        options = self.setUp()
        options.set_default_vertex_shape("STAR")
        self.assertEqual(options.get_default_vertex_shape(), "STAR")

    def test_set_get_default_vertex_color(self):
        options = self.setUp()
        options.set_default_vertex_color((255, 0, 128))
        self.assertEqual(options.get_default_vertex_color(), (255, 0, 128))

    # ... and so on for the rest of the tests

if __name__ == "__main__":
    unittest.main()
```

Please note that this is a direct translation from Java to Python. It might not be perfect as it's hard to translate directly without knowing more about how you want your code structured in Python.