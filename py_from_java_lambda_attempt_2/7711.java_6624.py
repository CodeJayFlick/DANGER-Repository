Here is the equivalent Python code:

```Python
class ValidFcgData:
    def __init__(self, function: 'Function', graph: 'Graph'):
        self.function = function
        self.graph = graph

    @property
    def get_function(self):
        return self.function

    def is_function(self, f) -> bool:
        return self.function == f

    @property
    def get_graph(self):
        return self.graph

    @property
    def get_function_edge_cache(self):
        # This should be replaced with the actual implementation of FunctionEdgeCache in Python.
        pass  # Replace this line.

    def has_results(self) -> bool:
        return True  # This object is always considered valid; use EmptyFcgData for bad Functions

    @property
    def is_initialized(self):
        return not self.graph.is_empty()

    def dispose(self):
        self.graph.dispose()  # This should be replaced with the actual implementation of disposing graph in Python.

    @property
    def get_graph_perspective(self) -> 'GraphPerspectiveInfo':
        pass  # Replace this line. The equivalent class and method would need to be implemented in Python.

    def set_graph_perspective(self, info: 'GraphPerspectiveInfo'):
        self.graph = info

class Function:
    pass  # This should be replaced with the actual implementation of a function in Python.

class Graph:
    def is_empty(self) -> bool:
        pass  # Replace this line. The equivalent method would need to be implemented in Python.

    def dispose(self):
        pass  # Replace this line. The equivalent method would need to be implemented in Python.
```

Please note that the above code does not include actual implementations of classes like `Function`, `Graph` and their methods, as they are specific to Java/GHIDRA framework which is not directly applicable to Python.