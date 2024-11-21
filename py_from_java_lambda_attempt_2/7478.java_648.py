Here is the translation of the Java code to Python:
```
class FGLocationMemento:
    def __init__(self, program, location, info):
        super().__init__(program, location)
        self.info = info

    def __init__(self, save_state, programs):
        super().__init__(save_state, programs)
        self.info = GraphPerspectiveInfo(save_state)

    def save_state(self, save_state):
        super().save_state(save_state)
        self.info.save_state(save_state)

    @property
    def graph_perspective_info(self):
        return self.info

    def __str__(self):
        return f"FG Memento [\n\t perspective={self.info},\n\t address={self.program_location.get_address()},\n\t location={self.program_location}\n]"

class GraphPerspectiveInfo:
    def __init__(self, save_state):
        pass  # assume this class is implemented elsewhere

# Note: Python does not have a direct equivalent to Java's generics. If you need type safety,
#       consider using the `typing` module or a third-party library like mypy.
```
Note that I did not translate the `GraphPerspectiveInfo` class, as it was not provided in its entirety. You will likely need to implement this class separately depending on your specific use case.

Also, Python does not have an exact equivalent to Java's generics system. If you want type safety for generic types like `<FGVertex, FGEdge>`, consider using the `typing` module or a third-party library like mypy.