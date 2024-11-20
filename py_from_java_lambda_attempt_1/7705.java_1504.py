Here's your Java interface translated into a Python class:

```Python
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
```

Please note that the `Function`, `FunctionCallGraph`, and `FcgVertex` classes are not defined in this code. You would need to define them or import them from another module if they exist elsewhere.

Also, Python does not have direct support for interfaces like Java's interface keyword. Instead, we use abstract base classes (ABCs) with the `@abstractmethod` decorator to achieve similar functionality.