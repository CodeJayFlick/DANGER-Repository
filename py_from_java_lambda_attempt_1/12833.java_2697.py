Here is the translation of the Java code to Python:
```
class DummyGraphDisplayListener:
    def graph_closed(self):
        # I'm a dummy
        pass

    def clone_with(self, graph_display: 'GraphDisplay') -> 'DummyGraphDisplayListener':
        return self.__class__()

    def selection_changed(self, vertices: set) -> None:
        # I'm a dummy
        pass

    def location_focus_changed(self, vertex: object) -> None:
        # I'm a dummy
        pass

    def dispose(self) -> None:
        # I'm a dummy
        pass
```
Note that Python does not have an exact equivalent to Java's `package` statement or the Apache License header. The code is simply defined as a class in Python, with methods corresponding to the original Java methods.

Also, Python 3.x has type hints (e.g., `-> 'DummyGraphDisplayListener'`) which are used here for clarity and documentation purposes only; they do not affect the runtime behavior of the code.