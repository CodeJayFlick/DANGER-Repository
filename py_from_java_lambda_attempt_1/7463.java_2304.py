Here is the translation of the given Java code into equivalent Python:

```Python
class FunctionGraphEditableVertexLocationActionContext:
    def __init__(self, function_graph_provider: 'FGProvider', vertex_info: 'VertexActionContextInfo'):
        super().__init__(function_graph_provider, function_graph_provider)

        if not isinstance(vertex_info, VertexActionContextInfo):
            raise TypeError("VertexActionContextInfo must be an instance of VertexActionContextInfo")

        self.vertex_info = vertex_info

    def get_vertex(self) -> 'FGVertex':
        return self.vertex_info.get_active_vertex()

    def get_vertex_info(self) -> 'VertexActionContextInfo':
        return self.vertex_info

    def get_selected_vertices(self) -> set:
        return self.vertex_info.get_selected_vertices()
```

Note that Python does not have direct equivalent of Java's `package`, `import` statements. Also, Python uses indentation to denote block-level structure in the code, unlike Java which uses curly braces.

In this translation:

- The class is defined using the `class` keyword.
- The constructor (`__init__`) takes two parameters: `function_graph_provider` and `vertex_info`.
- The `super().__init__(...)` call initializes the parent class (in this case, `ListingActionContext`).
- The type hints are used to specify the expected types of variables or function arguments. These are not enforced at runtime in Python.
- The method definitions use the `def` keyword and follow a similar structure to their Java counterparts.
- The return types for methods are specified using the arrow (`->`) symbol, followed by the expected return type (e.g., `'FGVertex'`).