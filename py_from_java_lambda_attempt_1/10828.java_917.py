Here is the translation of the Java code into Python:

```Python
class LayoutPositions:
    def __init__(self):
        self.vertex_locations = {}
        self.edge_articulations = {}

    @staticmethod
    def create_empty_positions():
        return LayoutPositions()

    @staticmethod
    def get_current_positions(graph, graph_layout):
        locations = {}
        vertices = list(graph.get_vertices())
        for vertex in vertices:
            locations[vertex] = graph_layout.apply(vertex)

        articulations = {}
        edges = list(graph.get_edges())
        for edge in edges:
            articulations[edge] = edge.get_articulation_points()

        return LayoutPositions(locations, articulations)

    def set_vertex_locations(self, new_vertex_locations):
        self.vertex_locations = {k: v.copy() for k, v in new_vertex_locations.items()}

    def set_edge_articulations(self, new_edge_articulations):
        self.edge_articulations = {k: [v.copy() for v in vs] for k, vs in new_edge_articulations.items()}

    @property
    def vertex_locations(self):
        return self.vertex_locations

    @vertex_locations.setter
    def vertex_locations(self, value):
        self.set_vertex_locations(value)

    @property
    def edge_articulations(self):
        return self.edge_articulations

    @edge_articulations.setter
    def edge_articulations(self, value):
        self.set_edge_articulations(value)

    def dispose(self):
        self.vertex_locations.clear()
        self.edge_articulations.clear()

# Example usage:
graph = ...  # Your graph object
graph_layout = ...  # Your graph layout object

positions = LayoutPositions.get_current_positions(graph, graph_layout)
print(positions.vertex_locations)  # Print the vertex locations
print(positions.edge_articulations)  # Print the edge articulations

# Modify the positions:
positions.set_vertex_locations({k: (x + 1, y + 1) for k, (x, y) in positions.vertex_locations.items()})
positions.set_edge_articulations({k: [(x + 2, y + 3), (x - 4, y - 5)] for k, vs in positions.edge_articulations.items()})

# Dispose the positions:
positions.dispose()
```

Note that Python does not have direct equivalents to Java's generics or static methods. The `create_empty_positions` and `get_current_positions` methods are implemented as class-level functions instead of static methods.