Here is the translation of the Java code to Python:
```
class EmptyIcon:
    def __init__(self, width: int, height: int):
        self.width = width
        self.height = height

    @property
    def icon_height(self) -> int:
        return self.height

    @property
    def icon_width(self) -> int:
        return self.width

    def paint_icon(self, c=None, g=None, x=0, y=0):
        pass  # no-op
```
Note that I've used Python's `@property` decorator to create read-only properties for the `icon_height` and `icon_width` attributes. This is equivalent to Java's getter methods.

Also, in Python, we don't need explicit type declarations like `int width;`, so I omitted those.