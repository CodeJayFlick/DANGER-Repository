Here is the translation of the given Java code into Python:

```Python
class Rectangle:
    def __init__(self, left: int, top: int, right: int, bottom: int):
        self.left = left
        self.top = top
        self.right = right
        self.bottom = bottom

    @property
    def get_left(self) -> int:
        return self.left

    @property
    def get_right(self) -> int:
        return self.right

    @property
    def get_top(self) -> int:
        return self.top

    @property
    def get_bottom(self) -> int:
        return self.bottom

    def intersectsWith(self, r: 'Rectangle') -> bool:
        if (r.get_left() > self.right or r.get_right() < self.left or 
            r.get_top() > self.bottom or r.get_bottom() < self.top):
            return False
        else:
            return True

    def __str__(self) -> str:
        return f"({self.left},{self.top},{self.right},{self.bottom})"
```

Note that Python does not have a direct equivalent to Java's `@Getter` and `@RequiredArgsConstructor`, so I've implemented the getter methods manually. Also, in Python, we don't need to explicitly define getters for properties like we do in Java with Lombok.