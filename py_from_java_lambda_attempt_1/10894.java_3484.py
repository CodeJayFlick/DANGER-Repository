Here is the translation of the Java code into Python:

```Python
class AbstractFilteringVisualGraphTest:
    def __init__(self):
        self.graph = None

    def assert_no_edges_filtered(self):
        assert len(self.get_filtered_edges()) == 0

    def assert_no_vertices_filtered(self):
        assert len(self.get_filtered_vertices()) == 0

    def assert_filtered(self, *edges):
        for edge in edges:
            assert edge in self.get_filtered_edges()
            assert edge in self.get_all_edges()

    def assert_unfiltered(self, *edges):
        filtered_edges = set(self.get_filtered_edges())
        all_edges = set(self.get_all_edges())
        for edge in edges:
            assert edge not in filtered_edges
            assert edge in all_edges

    def assert_filtered_vertices(self, *vertices):
        filtered_vertices = set(self.get_filtered_vertices())
        all_vertices = set(self.get_all_vertices())
        for vertex in vertices:
            assert vertex in filtered_vertices
            assert vertex in all_vertices

    def assert_only_these_are_filtered(self, *vertices):
        filtered_vertices = set(self.get_filtered_vertices())
        all_vertices = set(self.get_all_vertices())
        assert len(vertices) == len(filtered_vertices)
        for vertex in vertices:
            assert vertex in filtered_vertices
            assert vertex in all_vertices

    def assert_unfiltered_vertices(self, *vertices):
        for vertex in vertices:
            assert vertex not in self.get_filtered_vertices()
            assert vertex in self.get_all_vertices()

    def assert_not_in_graph(self, *vertices):
        for vertex in vertices:
            assert vertex not in self.get_all_vertices()

    def get_filtered_vertices(self):
        return set(self.graph.filtered_vertices)

    def get_unfiltered_vertices(self):
        return set(self.graph.unfiltered_vertices)

    def get_all_vertices(self):
        return set(self.graph.all_vertices)

    def get_filtered_edges(self):
        return set(self.graph.filtered_edges)

    def get_unfiltered_edges(self):
        return set(self.graph.unfiltered_edges)

    def get_all_edges(self):
        return set(self.graph.all_edges)

    def vertex(self, id):
        v = LabelTestVertex(id)
        if v in self.get_all_vertices():
            return v
        self.graph.add_vertex(v)
        return v

    def edge(self, start, end):
        e = TestEdge(start, end)
        if e in self.get_all_edges():
            return e
        self.graph.add_edge(e)
        return e

    def size_of(self, c):
        return len(c)

class LabelTestVertex:
    pass

class TestEdge:
    pass
```

Please note that the `LabelTestVertex` and `TestEdge` classes are not implemented in this translation. They should be replaced with your actual vertex and edge implementations.