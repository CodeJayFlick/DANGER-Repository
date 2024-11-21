Here is the translation of the Java code to Python:
```python
class VisualGraphEdgeSatelliteRenderer(VirtualVertex, VirtualEdge):
    def __init__(self, delegate):
        self.renderer_delegate = delegate

    def is_in_hovered_vertex_path(self, edge):
        return False

    def is_in_focused_vertex_path(self, edge):
        return False

    def is_selected(self, edge):
        return False

    def is_emphasized(self, edge):
        return False

    def get_edge_shape(self, render_context, graph, edge, x1, y1, x2, y2, is_loop, vertex_shape):
        return self.renderer_delegate.get_edge_shape(render_context, graph, edge, x1, y1, x2, y2, is_loop, vertex_shape)

    def get_vertex_shape_for_arrow(self, render_context, layout, vertex):
        # we use the default shape (the full shape) for arrow detection
        return self.get_compact_shape(render_context, layout, vertex)
```
Note that I've used Python's built-in `class` syntax to define a class, and replaced Java-specific constructs like packages, imports, and annotations with equivalent Python constructs.