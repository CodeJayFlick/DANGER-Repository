Here is the translation of the Java code to Python:
```
class VgVertexContext(VgActionContext):
    def __init__(self, provider: 'ComponentProvider', v: 'VisualVertex') -> None:
        super().__init__(provider)
        self.v = v

    @property
    def vertex(self) -> 'VisualVertex':
        return self.v

    def should_show_satellite_actions(self) -> bool:
        return False  # not satellite actions when we are over a vertex
```
Note that I used the `-> None` syntax to indicate that the method returns no value, and the `'ComponentProvider'` and `'VisualVertex'` strings as type hints. This is because Python does not have an equivalent concept to Java's generics or annotations.

Also, in Python, we don't need to override methods explicitly like you would do in Java with `@Override`. Instead, if a method has the same name and signature (including return type) as its parent class, it will be called automatically.