Here is the translation of the Java code to Python:
```
from typing import Optional

class CakeToppingInfo:
    def __init__(self, id: Optional[int] = None, name: str = "", calories: int = 0):
        self.id = id
        self.name = name
        self.calories = calories

    @property
    def id(self) -> Optional[int]:
        return self._id

    @id.setter
    def id(self, value: Optional[int]):
        if isinstance(value, int):
            self._id = value
        else:
            self._id = None

    def __str__(self) -> str:
        return f"CakeToppingInfo(id={self.id}, name='{self.name}', calories={self.calories})"
```
Note that I used the `Optional` type from the `typing` module to represent the optional `Long` field in Java. In Python, we don't have a built-in equivalent of Java's `Optional`, so I used an integer with default value `None` to indicate absence of ID.

I also replaced the two constructors with a single constructor that takes three arguments (ID, name, and calories), and added property setters for the `id` field. The `__str__` method is equivalent to Java's `toString()` method.