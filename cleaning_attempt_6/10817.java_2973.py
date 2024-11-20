class AbstractLayoutProvider(VV, EE, GG):
    def __init__(self):
        pass

    def get_action_icon(self):
        return None

    def get_priority_level(self):
        return 0

    def init_vertex_locations(self, g: GG, layout: Layout) -> None:
        vertices = list(g.get_vertices())
        for v in vertices:
            p = layout.apply(v)
            v.set_location(p)

class VisualVertex:
    def __init__(self):
        pass

    def set_location(self, location):
        pass

class VisualEdge(VV):
    def __init__(self, vertex: VV):
        self.vertex = vertex
