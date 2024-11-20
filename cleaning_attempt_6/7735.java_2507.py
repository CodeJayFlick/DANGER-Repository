class EdgeComparator:
    def __init__(self, renderer):
        self.renderer = renderer

    def compare(self, edge1: 'AttributedEdge', edge2: 'AttributedEdge') -> int:
        edge_type1 = edge1.get_edge_type()
        edge_type2 = edge2.get_edge_type()

        if edge_type1 is None and edge_type2 is None:
            return 0
        elif edge_type1 is None:
            return 1
        elif edge_type2 is None:
            return -1

        priority1 = self.renderer.get_edge_priority(edge_type1)
        priority2 = self.renderer.get_edge_priority(edge_type2)

        return priority1.compare_to(priority2)
