class FunctionGraphVertexLocationContext:
    def __init__(self):
        pass

    def get_vertex(self) -> 'FGVertex':
        raise NotImplementedError("Must be implemented by subclass")

    def get_vertex_info(self) -> dict:
        return {}
