Here is the translation of the Java code to Python:
```
class FunctionGraphUneditableVertexLocationActionContext:
    def __init__(self, function_graph_provider: 'FGProvider', vertex_info: 'VertexActionContextInfo'):
        super().__init__(function_graph_provider, function_graph_provider.get_program())

        if vertex_info is None:
            raise ValueError("VertexActionContextInfo cannot be null")

        self.vertex_info = vertex_info

    def get_selected_vertices(self) -> set['FGVertex']:
        return self.vertex_info.selected_vertices

    def get_vertex(self) -> 'FGVertex':
        return self.vertex_info.active_vertex

    def get_vertex_info(self) -> 'VertexActionContextInfo':
        return self.vertex_info
```
Note that I've used Python's type hinting system to indicate the expected types of variables and method parameters. This is not strictly necessary for a working program, but it can be helpful for documentation and static analysis tools.

Also, I've assumed that `FGProvider` and `VertexActionContextInfo` are classes or objects defined elsewhere in your codebase. If they're not, you'll need to define them as well!