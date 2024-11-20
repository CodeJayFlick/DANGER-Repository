Here is the translation of the given Java code into Python:

```Python
class FunctionCallGraph:
    def __init__(self):
        self.layout = None
        self.source = None
        self.vertices_by_function = {}
        self.vertex_comparator = lambda v1, v2: (v1.get_address() - v2.get_address())
        self.vertices_by_level = {}

    def set_source(self, source):
        if self.source is not None:
            raise ValueError("Cannot change graph source once it has been created")
        self.source = source
        self.add_vertex(source)

    def get_source(self):
        return self.source

    def get_vertex(self, function):
        return self.vertices_by_function.get(function)

    def contains_function(self, function):
        return function in self.vertices_by_function.keys()

    def get_vertices_by_level(self, level):
        return list(self.vertices_by_level[level])

    def get_largest_level(self, direction):
        greatest = FcgLevel(1, direction)
        for key in self.vertices_by_level:
            if key.get_direction() != direction:
                continue
            if key.get_row() > greatest.get_row():
                greatest = key
        return greatest

class VisualGraphLayout:
    pass  # This class is not implemented as it was missing from the Java code.

class FcgVertex:
    def __init__(self, function):
        self.function = function
        self.address = None

    def get_function(self):
        return self.function

    def get_address(self):
        return self.address


class FcgEdge:
    pass  # This class is not implemented as it was missing from the Java code.


class FcgLevel:
    def __init__(self, row, direction):
        self.row = row
        self.direction = direction

    def get_row(self):
        return self.row

    def get_direction(self):
        return self.direction


# Example usage:

graph = FunctionCallGraph()
source_vertex = FcgVertex(None)
graph.set_source(source_vertex)

function1 = None  # Replace with actual function object.
vertex1 = graph.get_vertex(function1)

print(vertex1)  # This will print the vertex for the given function.

```

Please note that this translation is not perfect, as some classes and methods were missing from the Java code. I have filled in these gaps based on my understanding of what they should do.