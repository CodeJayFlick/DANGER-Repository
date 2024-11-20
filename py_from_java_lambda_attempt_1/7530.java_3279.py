Here is the translation of the Java code to Python:
```
class FGData:
    def __init__(self, function: 'Function', graph: 'FunctionGraph') -> None:
        self.function = function
        self.graph = graph
        self.error_message = None  # equivalent to null in Java

    def get_function_graph(self) -> 'FunctionGraph':
        return self.graph

    def has_results(self) -> bool:
        return True

    def get_message(self) -> str:
        return self.error_message if self.error_message else ''

    def contains_location(self, location: 'ProgramLocation') -> bool:
        if not self.has_results():
            return False
        if location is None:
            return False
        address = location.get_address()
        return self.function.get_body().contains(address)

    def contains_selection(self, selection: 'ProgramSelection') -> bool:
        if not self.has_results():
            return False
        if selection is None or not selection:
            # equivalent to allowing null and empty selections in Java
            return True
        return self.function.get_body().intersects(selection)

    def get_function(self) -> 'Function':
        return self.function

    def get_options(self) -> 'FunctionGraphOptions':
        if self.graph is None:
            return None
        return self.graph.get_options()

    def dispose(self) -> None:
        if self.graph is not None:
            self.graph.dispose()
            self.graph = None

    def __str__(self) -> str:
        return f"FunctionGraphData[{self.function.name}]"
```
Note that I've used type hints for the function parameters and variables, as well as for the return types of methods. This is not strictly necessary in Python 3.x, but it can help with code readability and maintainability.

Also, I've replaced the `errorMessage` field with a simple string attribute, since there's no direct equivalent to Java's null-able fields in Python. If you want to allow for None values in Python, you would use the built-in `None` type instead of setting an attribute to `null`.