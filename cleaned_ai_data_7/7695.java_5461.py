class BowTieLayout:
    def __init__(self, graph, name):
        pass  # equivalent to super(graph, name)

    def create_cloned_layout(self, new_graph):
        if not isinstance(new_graph, FunctionCallGraph):
            raise ValueError("Must pass a FunctionCallGraph")
        return self.__class__(new_graph, self.get_name())

    @property
    def get_visual_graph(self):
        return self.graph

    def perform_initial_grid_layout(self, g):
        if not isinstance(g, FunctionCallGraph):
            raise ValueError("This layout can only be used with the FunctionCallGraph")
        return self.layout_function_call_graph(g)

    def calculate_locations(self, g, task_monitor=None):
        locs = super().calculate_locations(g, task_monitor)
        # TODO put x offset manipulation here...
        return locs

    def get_vertex_location(self, v, col, row, bounds):
        return self.get_centered_vertex_location(v, col, row, bounds)

    @property
    def is_condensed_layout(self):
        return True  # not sure about this

    def layout_function_call_graph(self, g):
        grid = {}
        source = next(iter(g.vertices))
        
        in_edges = [edge for edge in g.edges if edge.start == source]
        in_vertices = sorted([vertex for edge in in_edges for vertex in (edge.end,)])
        row = 0
        for col, v in enumerate(in_vertices):
            grid[(v,)] = (row, col)
        
        row += 1
        grid[(source,)] = (row, 0)

        out_edges = [edge for edge in g.edges if edge.end == source]
        out_vertices = sorted([vertex for edge in out_edges for vertex in (edge.start,)])
        out_vertices -= set(in_vertices)
        row += 1
        for col, v in enumerate(out_vertices):
            grid[(v,)] = (row, col)

        self.center_rows(grid)

        return grid

    def center_rows(self, grid):
        pass  # equivalent to super().centerRows()

class FunctionCallGraph:
    @property
    def get_source(self):
        raise NotImplementedError("Must be implemented")

    @property
    def vertices(self):
        raise NotImplementedError("Must be implemented")

    @property
    def edges(self):
        raise NotImplementedError("Must be implemented")
