Here is the translation of the Java code to Python:
```
import typing as t

class VTMatchOneToManyContext:
    def __init__(self, provider: object, selected_items: t.List[t.Any]) -> None:
        super().__init__(provider, None)
        self.selected_items = selected_items

    @property
    def selected_matches(self) -> t.List[object]:
        return self.selected_items
```
Note that I used the `typing` module to define a list of any type (`t.List[t.Any]`) and an object (`t.Any`). This is equivalent to Java's raw types.

Also, in Python, we don't need explicit getters and setters like in Java. Instead, we can use properties (defined using the `@property` decorator) to provide read-only access to the `selected_items` attribute.