Here is the translation of the Java code to Python:
```
class CakeLayerInfo:
    def __init__(self, id: Optional[int] = None, name: str = "", calories: int = 0):
        self.id = id
        self.name = name
        self.calories = calories

    def __str__(self) -> str:
        return f"CakeLayerInfo(id={self.id}, name='{self.name}', calories={self.calories})"

from typing import Optional

Optional.__init__()
```
Note that I used the `f` string notation to create a formatted string in the `__str__` method, which is equivalent to Java's `String.format()`.

Also, I used Python's built-in `int`, `str`, and `None` types instead of Java's specific classes.