import unittest

class GraphType:
    def __init__(self):
        self.name = None
        self.description = None
        self.vertex_types = []
        self.edge_types = []

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, value):
        self._name = value

    @property
    def description(self):
        return self._description

    @description.setter
    def description(self, value):
        self._description = value if value else self.name

    def get_vertex_types(self):
        return self.vertex_types[:]

    def add_vertex_type(self, vertex_type):
        self.vertex_types.append(vertex_type)

    def get_edge_types(self):
        return self.edge_types[:]

    def add_edge_type(self, edge_type):
        self.edge_types.append(edge_type)


class GraphTypeBuilder:
    def __init__(self, name):
        self.graph_type = GraphType()
        self.graph_type.name = name

    def description(self, value):
        self.graph_type.description = value
        return self

    def vertex_type(self, vertex_type):
        self.graph_type.add_vertex_type(vertex_type)
        return self

    def edge_type(self, edge_type):
        self.graph_type.add_edge_type(edge_type)
        return self

    def build(self):
        return self.graph_type


class TestGraphTypeBuilder(unittest.TestCase):

    def test_name(self):
        graph_type = GraphTypeBuilder("Test").build()
        self.assertEqual(graph_type.name, "Test")

    def test_description(self):
        graph_type = GraphTypeBuilder("Test").description("abc").build()
        self.assertEqual(graph_type.description, "abc")

    def test_no_description_uses_name(self):
        graph_type = GraphTypeBuilder("Test").build()
        self.assertEqual(graph_type.description, "Test")

    def test_vertex_types(self):
        graph_type = GraphTypeBuilder("Test") \
            .vertex_type("V1") \
            .vertex_type("V2") \
            .build()

        vertex_types = graph_type.get_vertex_types()
        self.assertEqual(len(vertex_types), 2)
        self.assertEqual(vertex_types[0], "V1")
        self.assertEqual(vertex_types[1], "V2")

    def test_edge_types(self):
        graph_type = GraphTypeBuilder("Test") \
            .edge_type("E1") \
            .edge_type("E2") \
            .build()

        edge_types = graph_type.get_edge_types()
        self.assertEqual(len(edge_types), 2)
        self.assertEqual(edge_types[0], "E1")
        self.assertEqual(edge_types[1], "E2")


if __name__ == '__main__':
    unittest.main()
