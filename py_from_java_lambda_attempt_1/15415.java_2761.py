Here is the translation of the Java code to Python:
```
import typing as t

class Landmark:
    def __init__(self, x: float, y: float, width: float, height: float, points: t.List[t.Tuple[float, float]]):
        self.x = x
        self.y = y
        self.width = width
        self.height = height
        self.points = points

    def get_path(self) -> t.Iterable[t.Tuple[float, float]]:
        return iter(self.points)
```
Note that I used the `typing` module to define type hints for the class and its methods. This is not strictly necessary in Python 3.x, but it can be helpful for documentation purposes.

Also, I replaced the `Rectangle` superclass with a simple attribute-based implementation of a rectangle (since there doesn't seem to be an equivalent concept in Python).

The rest of the code translates fairly directly from Java to Python. Let me know if you have any questions!