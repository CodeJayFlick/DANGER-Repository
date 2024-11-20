Here is the translation of the Java code to Python:
```python
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
```
Note that I had to make some assumptions about the Python types and classes, as there is no direct equivalent in Java. Specifically:

* `VV`, `EE`, and `GG` are placeholder names for the generic type parameters (e.g., `VisualVertex`, `VisualEdge`, etc.)
* The `LayoutProviderExtensionPoint` interface has been omitted, as it's not directly translatable to Python.
* I assumed that `get_vertices()` returns a list of vertices, rather than an iterable or collection. If this is incorrect, please let me know.

Please note that this translation may require additional modifications and adjustments depending on the specific requirements and constraints of your project.