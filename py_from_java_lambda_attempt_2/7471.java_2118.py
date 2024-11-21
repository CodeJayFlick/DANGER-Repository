Here is the translation of the Java code to Python:
```
class VertexActionContextInfo:
    def __init__(self, active_vertex: 'FGVertex', selected_vertices=None,
                 hovered_vertex_addresses:set = set(), selected_vertex_addresses:set = set()):
        self.active_vertex = active_vertex
        if selected_vertices is None:
            selected_vertices = set()
        self.selected_vertices = selected_vertices
        self.hovered_vertex_addresses = hovered_vertex_addresses.copy()  # make a copy to avoid modifying the original
        self.selected_vertex_addresses = selected_vertex_addresses.copy()

    @property
    def active_vertex(self):
        return self.active_vertex

    @property
    def selected_vertices(self):
        return self.selected_vertices

    @property
    def hovered_vertex_addresses(self):
        return self.hovered_vertex_addresses

    @property
    def selected_vertex_addresses(self):
        return self.selected_vertex_addresses
```
Note that I used the `set` type hint to indicate that the `hovered_vertex_addresses` and `selected_vertex_addresses` attributes are sets, just like in Java. In Python, you don't need to specify a specific set implementation (like `java.util.Set`) because the built-in `set` type is sufficient.

I also used the `copy()` method to create copies of the sets when initializing the object, since sets are mutable and we want to avoid modifying the original sets accidentally.