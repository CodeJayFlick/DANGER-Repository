class GraphTypeBuilder:
    def __init__(self, name):
        self.vertex_types = []
        self.edge_types = []
        self.name = name
        self.description = name

    def description(self, text):
        self.description = text
        return self

    def vertex_type(self, type):
        self.vertex_types.append(type)
        return self

    def edge_type(self, type):
        self.edge_types.append(type)
        return self

    def build(self):
        from graph import GraphType  # Assuming you have a separate file 'graph.py' with the definition of class GraphType
        return GraphType(self.name, self.description, self.vertex_types, self.edge_types)

# Example usage:
builder = GraphTypeBuilder("MyGraph")
my_graph = builder.description("This is my graph").vertex_type("Vertex1").edge_type("Edge1").build()
