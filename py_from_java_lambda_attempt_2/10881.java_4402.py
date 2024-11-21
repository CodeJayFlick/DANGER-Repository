Here is the translation of the Java code to Python:

```Python
class GraphType:
    def __init__(self, name: str, description: str, vertex_types: list[str], edge_types: list[str]):
        self.name = name
        self.description = description
        self.vertex_types = frozenset(vertex_types)
        self.edge_types = frozenset(edge_types)

    @property
    def name(self) -> str:
        return self._name

    @property
    def description(self) -> str:
        return self._description

    @property
    def vertex_types(self) -> list[str]:
        return list(self._vertex_types)

    @property
    def edge_types(self) -> list[str]:
        return list(self._edge_types)

    def contains_vertex_type(self, vertex_type: str) -> bool:
        return vertex_type in self.vertex_types

    def contains_edge_type(self, edge_type: str) -> bool:
        return edge_type in self.edge_types

    def __hash__(self):
        return hash((self.name, self.description, frozenset(self.edge_types), frozenset(self.vertex_types)))

    def __eq__(self, other):
        if not isinstance(other, GraphType):
            return False
        return (self.name == other.name and 
                self.description == other.description and 
                self.edge_types == other.edge_types and 
                self.vertex_types == other.vertex_types)
```

Note that I used the `frozenset` type to represent sets of strings in Python, since it is immutable. This means you can't modify a frozen set after creating it, which matches the behavior of Java's unmodifiable set.