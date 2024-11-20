class FcgData:
    def __init__(self):
        pass

    def get_function(self) -> 'Function':
        # Implement this method in subclass
        raise NotImplementedError("Method not implemented")

    def get_graph(self) -> 'FunctionCallGraph':
        # Implement this method in subclass
        raise NotImplementedError("Method not implemented")

    def get_function_edge_cache(self) -> 'FunctionEdgeCache':
        # Implement this method in subclass
        raise NotImplementedError("Method not implemented")

    @property
    def has_results(self):
        return False  # Default value

    @property
    def is_initialized(self):
        return False  # Default value

    def dispose(self):
        pass  # No implementation needed for now

    def get_graph_perspective(self) -> 'GraphPerspectiveInfo[FcgVertex, FcgEdge]':
        # Implement this method in subclass
        raise NotImplementedError("Method not implemented")

    def set_graph_perspective(self, info: 'GraphPerspectiveInfo[FcgVertex, FcgEdge]'):
        pass  # No implementation needed for now

    def is_function(self, f) -> bool:
        return False  # Default value
