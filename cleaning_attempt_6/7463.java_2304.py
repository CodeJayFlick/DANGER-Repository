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
