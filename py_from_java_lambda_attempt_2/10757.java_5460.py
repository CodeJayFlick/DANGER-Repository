Here is the translation of the given Java code into equivalent Python:

```Python
class MoveVertexToCenterAnimatorFunctionGraphJob:
    def __init__(self, viewer, vertex, use_animation):
        self.vertex = vertex
        super().__init__(viewer, use_animation)

    def create_destination(self):
        return GraphViewerUtils.get_vertex_offset_from_layout_center(viewer, self.vertex)
```

Note that Python does not have direct equivalent of Java's generics. The type parameters `<V, E>` in the original code are removed as they do not translate directly to Python.

Also note that Python classes can be defined without explicit inheritance declaration (`extends` keyword), unlike Java where it is required for class inheritance.