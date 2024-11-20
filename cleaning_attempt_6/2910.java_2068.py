class SampleGraph:
    def __init__(self):
        self.layout = None

    def get_layout(self):
        return self.layout

    def copy(self):
        new_graph = SampleGraph()
        
        for v in self.vertices.keys():
            new_graph.add_vertex(v)
            
        for e in self.edges.keys():
            new_graph.add_edge(e)

        return new_graph

    def set_layout(self, layout):
        self.layout = layout


# Note: The above Python code assumes that you have a class SampleVertex and 
#       another class SampleEdge defined elsewhere. These classes should be similar to the Java ones.
