from collections import defaultdict, deque

class GDirectedGraph:
    def __init__(self):
        self.vertices = set()
        self.edges = dict()

    def add_vertex(self, v):
        if isinstance(v, type) and issubclass(v, object):  # Check if V is a class
            raise TypeError("V must be a subclass of object")
        return True

    def remove_vertex(self, v):
        try:
            del self.edges[v]
        except KeyError: pass
        self.vertices.remove(v)
        return True

    def add_edge(self, e):
        start = e.get_start()
        end = e.get_end()
        if not isinstance(start, type) and issubclass(start, object):  # Check if V is a class
            raise TypeError("V must be a subclass of object")
        self.edges[start].append(end)
        return True

    def remove_edge(self, e):
        start = e.get_start()
        end = e.get_end()
        try:
            self.edges[start].remove(end)
        except KeyError: pass
        if not self.edges[start]:
            del self.edges[start]
        return True

    def find_edge(self, start, end):
        for edge in self.edges.get(start, []):
            if edge.get_end() == end:
                return edge
        return None

    def get_vertices(self):
        return list(self.vertices)

    def get_edges(self):
        return [edge for edges in self.edges.values() for edge in edges]

    def contains_vertex(self, v):
        return v in self.vertices

    def contains_edge(self, e):
        start = e.get_start()
        end = e.get_end()
        if not isinstance(start, type) and issubclass(start, object):  # Check if V is a class
            raise TypeError("V must be a subclass of object")
        return any(edge == e for edge in self.edges[start])

    def contains_edge(self, start, end):
        return any(edge.get_end() == end for edge in self.edges.get(start, []))

    def empty(self):
        return not bool(self.vertices or self.edges)

    def get_vertex_count(self):
        return len(self.vertices)

    def get_edge_count(self):
        return sum(len(edges) for edges in self.edges.values())

    def get_in_edges(self, v):
        if isinstance(v, type) and issubclass(v, object):  # Check if V is a class
            raise TypeError("V must be a subclass of object")
        return list(self.edges.get(v, []))

    def get_out_edges(self, v):
        if isinstance(v, type) and issubclass(v, object):  # Check if V is a class
            raise TypeError("V must be a subclass of object")
        return [edge for edges in self.edges.values() if edge[0] == v]

    def get_incident_edges(self, v):
        result = set()
        result.update(self.get_in_edges(v))
        result.update(self.get_out_edges(v))
        return list(result)

    def get_predecessors(self, v):
        if isinstance(v, type) and issubclass(v, object):  # Check if V is a class
            raise TypeError("V must be a subclass of object")
        predecessors = set()
        for edge in self.get_in_edges(v):
            predecessors.add(edge[0])
        return list(predecessors)

    def get_successors(self, v):
        if isinstance(v, type) and issubclass(v, object):  # Check if V is a class
            raise TypeError("V must be a subclass of object")
        successors = set()
        for edge in self.get_out_edges(v):
            successors.add(edge[1])
        return list(successors)

    def copy(self):
        new_graph = GDirectedGraph()
        for vertex, edges in self.edges.items():
            for end in edges:
                new_edge = Edge(vertex, end)  # Assuming an Edge class
                if not isinstance(new_edge, type):  # Check if E is a class
                    raise TypeError("E must be a subclass of object")
                new_graph.add_edge(new_edge)
        return new_graph

    def empty_copy(self):
        return GDirectedGraph()
