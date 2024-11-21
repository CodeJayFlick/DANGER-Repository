class JungDirectedGraph:
    def __init__(self):
        pass

    def add_edge(self, e):
        super().add_edge(e, e.start, e.end)

    def remove_vertices(self, vertices_to_remove):
        for v in vertices_to_remove:
            super().remove_vertex(v)

    def remove_edges(self, edges_to_remove):
        for edge in edges_to_remove:
            super().remove_edge(edge)

    def contains_edge(self, from_node, to_node):
        return self.find_edge(from_node, to_node) is not None

    def empty_copy(self):
        new_graph = JungDirectedGraph()
        return new_graph

    def copy(self):
        new_graph = JungDirectedGraph()

        for v in self.vertices:
            new_graph.add_vertex(v)

        for edge in self.edges:
            new_graph.add_edge(edge)

        return new_graph

    def is_empty(self):
        return len(self.vertices) == 0
