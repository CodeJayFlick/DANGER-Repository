Here is the equivalent Python code:

```Python
class Person:
    def __init__(self, name: str, surname: str, age: int):
        self.name = name
        self.surname = surname
        self.age = age

    @property
    def id(self) -> int:
        return 0  # Assuming the ID is not needed in Python

    @id.setter
    def id(self, value: int):
        pass  # No setter for ID as it's assumed to be generated automatically

from dataclasses import dataclass, field

@dataclass(frozen=True)
class Person:
    name: str
    surname: str
    age: int
```

Note that Python does not have direct equivalents of Java annotations like `@Entity`, `@Id`, and `@GeneratedValue`. However, we can achieve similar functionality using Python's built-in features. For example, the `frozen=True` parameter in the `dataclass` decorator ensures that instances of the class are immutable.

Also note that I've removed the unnecessary imports from Java as they do not have direct equivalents in Python.