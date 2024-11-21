import jung.directed_graph as jung_directed_graph

class GraphFactory:
    def __init__(self):
        pass  # can't create this; (no equivalent in Python)

    @staticmethod
    def create_directed_graph():
        return jung_directed_graph.JungDirectedGraph()
