Here is the translation of the Java code to Python:
```
class DbgConsoleOutputEvent:
    def __init__(self, mask: int, info: str):
        self.info = info
        self.mask = mask

    @property
    def output(self) -> str:
        return self.info

    @property
    def mask(self) -> int:
        return self.mask
```
Note that I've used Python's built-in `class` syntax to define a class, and the `__init__` method is equivalent to Java's constructor. The `@property` decorator is used to create read-only properties for the `output` and `mask` attributes.

Also, in Python, we don't need explicit getters and setters like in Java; instead, we can use property decorators or simply access the attribute directly (e.g., `event.output`).