class FunctionGraphEmptyGraphActionContext:
    def __init__(self, function_graph_provider):
        super().__init__(function_graph_provider, function_graph_provider.get_program())

    def should_show_satellite_actions(self) -> bool:
        return True
