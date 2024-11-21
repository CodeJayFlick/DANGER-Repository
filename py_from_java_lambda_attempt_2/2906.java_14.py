Here's a translation of the provided Java code into equivalent Python:

```Python
import collections
from PIL import Image

class SampleGraphLayoutProvider:
    def __init__(self):
        self.default_icon = None  # Initialize default icon as None

    def get_layout(self, g: 'SampleGraph', monitor=None) -> 'VisualGraphLayout':
        pass  # Implement this method in your subclass

    def init_vertex_locations(self, g: 'SampleGraph', layout: dict) -> None:
        vertices = list(g.vertices())
        for v in vertices:
            p = layout.get(v)
            if p is not None:
                v.location = p
            else:
                raise ValueError(f"Vertex {v} has no location")

    def get_action_icon(self):
        return self.default_icon

class SampleGraphLayoutProviderAbstract(ABC):
    pass  # This class should be abstract in Python, but there's no direct equivalent to Java's "abstract"

# Example usage
if __name__ == "__main__":
    provider = SampleGraphLayoutProvider()
    g = SampleGraph()  # Implement this class and its methods
    layout = provider.get_layout(g)
    provider.init_vertex_locations(g, layout)

```

Please note that Python does not have direct equivalents to Java's abstract classes or interfaces. Instead, you can use the `ABC` (Abstract Base Class) from the `collections.abc` module.

Also, this code assumes a few things about your original Java code:

1. The `SampleVertex`, `SampleEdge`, and `SampleGraph` classes are implemented elsewhere in your program.
2. The `VisualGraphLayout` class is also implemented elsewhere or imported from another library (like NetworkX).
3. You have an equivalent of the ResourceManager to load images.

This Python translation does not include these implementations, as they would depend on specific details about how you're using those classes and resources in your original Java code.