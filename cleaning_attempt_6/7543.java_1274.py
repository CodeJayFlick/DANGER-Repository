class PendingFunctionGraphViewSettings:
    def __init__(self, copy_settings: 'FunctionGraphViewSettings', perspective):
        super().__init__(copy_settings)

        if not isinstance(perspective, dict) or "vertices" not in perspective or "edges" not in perspective:
            perspective = {"vertices": [], "edges": []}

        self.function_graph_perspective_info = perspective


class FunctionGraphViewSettings:
    pass
