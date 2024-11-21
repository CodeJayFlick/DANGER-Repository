class EmptyFunctionGraphData:
    def __init__(self, message):
        super().__init__(None, None, message)

    def get_function_graph(self):
        raise NotImplementedError("Empty data cannot have a graph")

    def get_options(self):
        raise NotImplementedError("Empty data cannot have a graph")

    def has_results(self):
        return False

    def __str__(self):
        return "EmptyFunctionGraphData"
