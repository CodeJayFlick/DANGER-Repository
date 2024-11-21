from collections import defaultdict, deque

class GImplicitDirectedGraph:
    def __init__(self):
        self.in_edges = {}
        self.out_edges = {}

    def get_in_edges(self, v):
        return self.in_edges.get(v, [])

    def set_in_edge(self, v, edge):
        if v not in self.in_edges:
            self.in_edges[v] = []
        self.in_edges[v].append(edge)

    def get_out_edges(self, v):
        return self.out_edges.get(v, [])

    def set_out_edge(self, v, edge):
        if v not in self.out_edges:
            self.out_edges[v] = []
        self.out_edges[v].append(edge)

    @property
    def predecessors(self):
        result = defaultdict(set)
        for v, edges in self.in_edges.items():
            for edge in edges:
                result[edge.get_end()].add(v)
        return dict(result)

    @property
    def successors(self):
        result = defaultdict(set)
        for v, edges in self.out_edges.items():
            for edge in edges:
                result[v].add(edge.get_start())
        return dict(result)

    def copy(self):
        new_graph = GImplicitDirectedGraph()
        for v, edges in self.in_edges.copy().items():
            for edge in edges:
                new_graph.set_in_edge(v, edge)
        for v, edges in self.out_edges.copy().items():
            for edge in edges:
                new_graph.set_out_edge(v, edge)
        return new_graph
