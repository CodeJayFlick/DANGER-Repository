class JungToGDirectedGraphAdapter:
    def __init__(self, delegate):
        self.delegate = delegate

    def add_edge(self, e):
        self.delegate.add_edge(e, e.start(), e.end())

    def contains_edge(self, from_vertex, to_vertex):
        return self.find_edge(from_vertex, to_vertex) is not None

    @staticmethod
    def empty_copy(delegate):
        if isinstance(delegate, GDirectedGraph):
            return delegate.empty_copy()
        
        try:
            new_graph = type(delegate)(*(None,))
            return JungToGDirectedGraphAdapter(new_graph)
        except Exception as e:
            Msg.show_error(None, None, "Error Creating Graph", f"Unable to create a new instance of graph: {type(delegate)}", e)
            return None

    def copy(self):
        new_graph = self.empty_copy(self.delegate)

        for v in self.delegate.get_vertices():
            new_graph.add_vertex(v)

        for e in self.delegate.get_edges():
            self.delegate.add_edge(e, e.start(), e.end())

        return new_graph

    @property
    def is_empty(self):
        return self.get_vertex_count() == 0

    @property
    def edges(self):
        return self.delegate.get_edges()

    @property
    def in_edges(self, vertex):
        return self.delegate.get_in_edges(vertex)

    @property
    def vertices(self):
        return self.delegate.get_vertices()

    @property
    def out_edges(self, vertex):
        return self.delegate.get_out_edges(vertex)

    def contains_vertex(self, vertex):
        return self.delegate.contains_vertex(vertex)

    def predecessors(self, vertex):
        return self.delegate.get_predecessors(vertex)

    def contains_edge_(self, edge):
        return self.delegate.contains_edge(edge)

    @property
    def edge_count(self):
        return self.delegate.get_edge_count()

    @property
    def successors(self, vertex):
        return self.delegate.get_successors(vertex)

    @property
    def vertex_count(self):
        return self.delegate.get_vertex_count()

    def neighbors(self, vertex):
        return self.delegate.get_neighbors(vertex)

    def in_degree(self, vertex):
        return self.delegate.in_degree(vertex)

    def incident_edges(self, vertex):
        return self.delegate.get_incident_edges(vertex)

    @property
    def out_degree(self, vertex):
        return self.delegate.out_degree(vertex)

    def incident_vertices(self, edge):
        return self.delegate.get_incident_vertices(edge)

    def is_predecessor(self, v1, v2):
        return self.delegate.is_predecessor(v1, v2)

    def is_successor(self, v1, v2):
        return self.delegate.is_successor(v1, v2)

    @property
    def find_edge(self, v1, v2):
        return self.delegate.find_edge(v1, v2)

    @property
    def predecessor_count(self, vertex):
        return self.delegate.get_predecessor_count(vertex)

    @property
    def successor_count(self, vertex):
        return self.delegate.get_successor_count(vertex)

    @property
    def source(self, edge):
        return self.delegate.get_source(edge)

    def find_edge_set(self, v1, v2):
        return self.delegate.find_edge_set(v1, v2)

    @property
    def dest(self, edge):
        return self.delegate.get_dest(edge)

    def is_source(self, vertex, edge):
        return self.delegate.is_source(vertex, edge)

    def is_dest(self, vertex, edge):
        return self.delegate.is_dest(vertex, edge)

    def add_vertex_(self, vertex):
        return self.delegate.add_vertex(vertex)

    @property
    def get_edge_type(self, edge):
        return self.delegate.get_edge_type(edge)
