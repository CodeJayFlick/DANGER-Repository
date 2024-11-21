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
